package main

import (
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/mitchellh/goamz/aws"
	"github.com/mitchellh/goamz/s3"
	"gopkg.in/mgo.v2"
)

type LogPackage struct {
	LogContent []byte
	Filename   string
}

type ProcessedLogRecord struct {
	Id string `bson:"_id"`
	// Processed bool   `bson:"time.Time"`
}

func getBucket(bucketName string, s3Client s3.S3) (s3.Bucket, error) {
	resp, err := s3Client.ListBuckets()
	empty := s3.Bucket{}

	if err != nil {
		return empty, err
	}

	var b s3.Bucket
	for bucket := range resp.Buckets {
		if bucketName == resp.Buckets[bucket].Name {
			b = resp.Buckets[bucket]
			glog.Info(fmt.Sprintf("bucket %v exists", bucketName))
		}
	}

	if b == empty {
		err := fmt.Errorf("bucket %v not found", bucketName)
		return s3.Bucket{}, err
	}
	return b, nil
}

func ShouldProcessLogfile(logfile string, sessionCopy *mgo.Session) bool {
	plr := ProcessedLogRecord{}
	logDoneC := sessionCopy.DB("cloudtrail").C("logDone")
	err := logDoneC.Find(ProcessedLogRecord{Id: logfile}).One(&plr)

	if err == mgo.ErrNotFound {
		if glog.V(1) {
			glog.Infof("already_processed_skipping: %v\n", logfile)
		}
		return true
	} else if err != nil {
		glog.Fatalf("looks like an error running find against mongo: %v", err)
	}
	if glog.V(1) {
		glog.Infof("will_process: %v\n", logfile)
	}
	return false
}

// DownloadFromBucket will download an object given the objects key and returns a []byte (decompressed if .gz)
func DownloadFromBucket(key string, s3Bucket s3.Bucket) ([]byte, error) {
	if glog.V(1) {
		glog.Infof("downloadingFileFromBucket: %v", key)
	}

	f, err := s3Bucket.Get(key)

	return f, err
}

func decomGzipData(reader io.ReadCloser) ([]byte, error) {
	decomReader, err := gzip.NewReader(reader)
	if err != nil {
		return []byte{}, err
	}

	defer decomReader.Close()
	bodyBytes, err := ioutil.ReadAll(decomReader)
	if err != nil {
		return []byte{}, err
	}

	return bodyBytes, nil
}

func getContent(r *http.Response) ([]byte, error) {

	if r.Header.Get("Content-Encoding") == "application/x-gzip" || r.Header.Get("Content-Type") == "application/x-gzip" {
		b, err := decomGzipData(r.Body)
		if err != nil {
			return []byte{}, err
		}
		return b, nil
	}

	b, err := ioutil.ReadAll(r.Body)

	if err != nil {
		return []byte{}, err
	}

	return b, nil

}

//GetLogFile takes an s3 key and downloads the contents, it expects the log to be compressed with gzip as per the default setting Cloudtrail uses
func GetLogFile(s3Key string, s3Bucket s3.Bucket) ([]byte, error) {

	//perform download from s3, this returns an http://golang.org/pkg/net/http/#Response
	r, err := s3Bucket.GetResponse(s3Key)
	if err != nil {
		return []byte{}, err
	}

	defer r.Body.Close()

	body, err := getContent(r)
	return body, err

}

func InsertLogEvent(event map[string]interface{}, sessionCopy *mgo.Session) error {
	s := sessionCopy.DB("cloudtrail").C("logs")
	if glog.V(2) {
		glog.Infof("insertingEvent: %v", event)
	}
	err := s.Insert(event)

	return err
}

func ProcessLogsStage1(logFiles *map[string]s3.Key, mgoMasterSession *mgo.Session, s3Bucket s3.Bucket, saveToDisk *string) {
	sessionCopy := mgoMasterSession.Copy()
	defer sessionCopy.Close()

	downloadChan := make(chan string, 4)
	processLogChan := make(chan LogPackage, 4)

	//function to download a logfile and pass to processLogChan for db inserting
	//will also save a copy to disk if saveToDisk is not ""
	download := func(id int, saveToDisk *string, wg *sync.WaitGroup) {

		defer glog.Infof("exit_downloader_%v", id)
		defer wg.Done()

		for d := range downloadChan {
			if glog.V(1) {
				glog.Infof("downloading(%v): %v", id, d)
			}

			log, err := GetLogFile(d, s3Bucket)
			if err != nil {
				glog.Errorf("fileDownloadFailed: %v", err)
				return
			}

			if glog.V(2) {
				glog.Info(string(log))
				glog.Info("send_to_processLogChan: %v", d)
			}

			processLogChan <- LogPackage{LogContent: log, Filename: d}

			if *saveToDisk != "" {
				if err := ioutil.WriteFile(path.Join("/tmp", filepath.Base(d)), log, 0755); err != nil {
					panic(err)
				}
			}
		}

	}

	if glog.V(2) {
		glog.Info("creating 4 downloaders and 2 Log Processors")
	}

	var downloadWG sync.WaitGroup
	downloadWG.Add(4)
	//pass downloadWG pointer to download func
	go download(1, saveToDisk, &downloadWG)
	go download(2, saveToDisk, &downloadWG)
	go download(3, saveToDisk, &downloadWG)
	go download(4, saveToDisk, &downloadWG)

	var processLogWG sync.WaitGroup
	processLogWG.Add(2)

	//pass processLogWG pointer to processLogChan func
	go ProcessLogfileFromChan(processLogChan, "p1", mgoMasterSession, s3Bucket, &processLogWG)
	go ProcessLogfileFromChan(processLogChan, "p2", mgoMasterSession, s3Bucket, &processLogWG)

	//range over each logfile and pass into download channel if not processed already
	for logFile := range *logFiles {
		if !strings.HasSuffix(logFile, "/") {

			process := ShouldProcessLogfile(logFile, sessionCopy)
			if process == true {
				if glog.V(2) {
					glog.Info("sendToDownloadChan:%v", logFile)
				}
				downloadChan <- logFile

			} else {
				if glog.V(1) {
					glog.Infof("skipping: %v\n", logFile)
				}
			}
		} else {
			if glog.V(1) {
				glog.Infof("skipping blank: %v", logFile)
			}
		}
	}

	//close channel once all logfiles have been sent to download channel, we wait for all go routiens to finish their tasks
	close(downloadChan)
	downloadWG.Wait()

	//now close processLogChan, this indicates no more logs will be sent for processing, then wait for remaining go routiens to finish inflight tasks
	close(processLogChan)
	processLogWG.Wait()
}

func ProcessLogfileFromChan(processChan chan LogPackage, name string, mgoMasterSession *mgo.Session, s3Bucket s3.Bucket, wg *sync.WaitGroup) {
	defer wg.Done()
	defer glog.Infof("Exit log processor #%v", name)

	var localWG sync.WaitGroup
	for i := range processChan {
		localWG.Add(1)
		go ProcessLogfile(i.LogContent, i.Filename, mgoMasterSession, s3Bucket, &localWG)
		glog.Infof("log_processor_%v - %v", name, i.Filename)
	}
	localWG.Wait()
}

func ProcessLogfile(log []byte, logFileName string, mgoMasterSession *mgo.Session, s3Bucket s3.Bucket, wg *sync.WaitGroup) {
	sessionCopy := mgoMasterSession.Copy()
	defer sessionCopy.Close()
	defer wg.Done()

	glog.Infof("processing: %v\n", logFileName)

	var m interface{}

	err := json.Unmarshal(log, &m)
	if err != nil {
		glog.Warningf("error_unmarshal_json: %v\n", logFileName)
		return
	}

	f := m.(map[string]interface{})
	c := f["Records"]

	switch vv := c.(type) {
	case []interface{}:
		var eventID string
		for _, u := range vv {

			dd := u.(map[string]interface{})

			eventID = fmt.Sprintf("%v", dd["eventID"])

			// add eventID as document _id and source_logfile_name for ref
			dd["_id"] = eventID
			dd["source_logfile_name"] = logFileName

			err := InsertLogEvent(dd, sessionCopy)
			if mgo.IsDup(err) {
				glog.Errorf("dup_event: %v log: %v", eventID, logFileName)
			}
		}

		glog.Infof("processed: %v events: %v\n", logFileName, len(vv))
		plr := ProcessedLogRecord{Id: logFileName}
		tmp := sessionCopy.DB("cloudtrail").C("logDone")
		tmp.Insert(plr)
	}

}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	var cloudtrailBucket = flag.String("ctbucket", "", "The bucket name where cloudtrail logs are stored")
	var mongodbAddr = flag.String("mongodb_addr", "127.0.0.1", "IP or FQDN or HOSTNAME of a mongo server, comma seperate names if more than one")
	var mongoConnectionTimeout = flag.Int("mtimeout", 3, "sets the timeout to wait while connecting to mongo, default 3 seconds")
	var saveLogsToDisk = flag.String("save_logs", "", "if set, logs are saved to this location as .json")
	var awsRegion = flag.String("aws_region", "", "AWS Region where the s3 bucket is located")
	var awsAccessKeyID = flag.String("aws_access_key_id", "", "AWS Access API Key, if not set, will check ENV, then IAM Role if available")
	var awsSecretAccessKey = flag.String("aws_secret_access_key", "", "AWS Secret Access Key API Key, if not set, will check ENV, then IAM Role if available")
	flag.Parse()

	glog.Infof("Cloudtrail bucket: %v", *cloudtrailBucket)
	glog.Infof("Mongo(s) address(es): %v", *mongodbAddr)
	glog.Info("connecting to Mongo...")

	timeOut := time.Duration(*mongoConnectionTimeout) * time.Second
	mgoMasterSession, err := mgo.DialWithTimeout(*mongodbAddr, timeOut)

	if err != nil {
		glog.Fatal(err)
	}

	glog.Infof("connected to Mongo: %v", *mongodbAddr)

	defer mgoMasterSession.Close()
	var auth aws.Auth

	if *awsAccessKeyID != "" && *awsSecretAccessKey != "" {
		auth, err = aws.GetAuth(*awsAccessKeyID, *awsSecretAccessKey)
	} else {
		auth, err = aws.GetAuth("", "")
	}

	var region aws.Region
	if *awsRegion != "" {
		region, err = aws.GetRegion(*awsRegion)
	} else {
		region, err = aws.GetRegion("")
	}

	if err != nil {
		panic(err)
	}

	client := s3.New(auth, region)

	s3Resp := client.Bucket(*cloudtrailBucket)

	logFiles, err := s3Resp.GetBucketContents()

	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	ProcessLogsStage1(logFiles, mgoMasterSession, *s3Resp, saveLogsToDisk)
	glog.Info("finished")
}
