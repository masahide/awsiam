package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

var (
	// Version is version number
	Version = "dev"
	// Date is build date
	Date            string
	roleArn         string
	roleSessionName string
	durationSeconds = 3600
	externalID      string
	policy          string
	serialNumber    string
	tokenCode       string
	showResult      bool
	showVer         bool
	user            string
	skipCreate      bool
	keyExpiration   = time.Duration(24) * time.Hour
)

func init() {
	flag.BoolVar(&showResult, "show", showResult, "show result")
	flag.StringVar(&user, "addUser", user, "add user name")
	flag.StringVar(&roleArn, "roleArn", roleArn, "role arn Ex:'arn:aws:iam::123456789012:role/role-name'")
	flag.StringVar(&roleSessionName, "roleSessionName", roleSessionName, "role session name")
	flag.IntVar(&durationSeconds, "durationSec", durationSeconds, "duration: 900-3600")
	flag.StringVar(&externalID, "externalId", externalID, "external ID")
	flag.StringVar(&policy, "policy", policy, " IAM policy in JSON format.")
	flag.StringVar(&serialNumber, "serialNumber", serialNumber, "The identification number of the MFA device that is associated with the user who is making the call.")
	flag.StringVar(&tokenCode, "tokencode", tokenCode, "The value provided by the MFA device, if the trust policy of the role being assumed requires MFA.")
	flag.BoolVar(&showVer, "version", showVer, "Show version")
	flag.BoolVar(&skipCreate, "skip", skipCreate, "Skip creation if user exists")
	flag.DurationVar(&keyExpiration, "keyExpiration", keyExpiration, "Accesskey expiration date")
	flag.Parse()
}

func nilString(s string) *string {
	if s != "" {
		return aws.String(s)
	}
	return nil
}

func main() {
	if showVer {
		fmt.Printf("version: %s %s\n", Version, Date)
		return
	}
	if user == "" {
		log.Print("Require -addUser option.")
		flag.PrintDefaults()
		return
	}
	sess := session.Must(session.NewSession())
	var creds *credentials.Credentials
	if roleArn != "" {
		if roleSessionName == "" {
			index := strings.LastIndex(roleArn, "/")
			roleName := roleArn[index+1:]
			roleSessionName = roleName + "-" + os.Getenv("USER")
		}
		creds = stscreds.NewCredentials(sess, roleArn, func(p *stscreds.AssumeRoleProvider) {
			p.RoleSessionName = roleSessionName
			p.Duration = time.Duration(durationSeconds) * time.Second
			p.ExternalID = nilString(externalID)
			p.Policy = nilString(policy)
			p.SerialNumber = nilString(serialNumber)
			p.TokenCode = nilString(tokenCode)
		})
		sess = session.Must(session.NewSession(aws.NewConfig().WithCredentials(creds)))
	}
	var res string
	switch {
	case user != "":
		var err error
		svc := iam.New(sess)
		res, err = addUser(svc, user)
		if err != nil {
			log.Fatal(err)
		}
	}
	if showResult {
		fmt.Println(res)
	}
}

func addUser(svc *iam.IAM, username string) (string, error) {
	res := ""
	cuParams := &iam.CreateUserInput{UserName: aws.String(user)}
	cuResp, err := svc.CreateUser(cuParams)
	if isAwsErr(entityAlreadyExists, err) {
		if !skipCreate {
			return res, err
		}
		res = "Already exists create user."
	} else if err != nil {
		return res, err
	} else {
		res = cuResp.String()
	}
	cakParams := &iam.CreateAccessKeyInput{UserName: aws.String(user)}
	cakResp, err := svc.CreateAccessKey(cakParams)
	if isAwsErr(limitExceeded, err) {
		if !skipCreate {
			return res, err
		}
		res = "Cannot exceed quota for AccessKeysPerUser: n"
	} else if err != nil {
		return res, err
	} else {
		res += "\n" + cakResp.String()
		return res, nil
	}
	duRes, err := deleteLeastUsedKey(svc, username)
	if err != nil {
		return res, err
	}
	res += "\n" + duRes
	cakResp, err = svc.CreateAccessKey(cakParams)
	if err != nil {
		return res, err
	}
	res += "\n" + cakResp.String()
	return res, err
}

const (
	entityAlreadyExists = "EntityAlreadyExists"
	limitExceeded       = "LimitExceeded"
)

func isAwsErr(code string, err error) bool {
	if awsErr, ok := err.(awserr.Error); ok {
		//log.Println("error code():", awsErr.Code())
		if awsErr.Code() == code {
			return true
		}
	}
	return false
}

func deleteLeastUsedKey(svc *iam.IAM, username string) (string, error) {
	params := &iam.ListAccessKeysInput{UserName: aws.String(username)}
	laResp, err := svc.ListAccessKeys(params)
	if err != nil {
		return "", err
	}
	leastKey := iam.AccessKeyMetadata{}
	leastDate := time.Now()
	for _, accessKey := range laResp.AccessKeyMetadata {
		lastUsed := *accessKey.CreateDate
		luParams := &iam.GetAccessKeyLastUsedInput{AccessKeyId: accessKey.AccessKeyId}
		resp, err := svc.GetAccessKeyLastUsed(luParams)
		if err != nil {
			return "", err
		}
		if resp.AccessKeyLastUsed != nil && resp.AccessKeyLastUsed.LastUsedDate != nil {
			lastUsed = *resp.AccessKeyLastUsed.LastUsedDate
		}
		if lastUsed.UnixNano() < leastDate.UnixNano() {
			leastDate = lastUsed
			leastKey = *accessKey
		}
	}
	if time.Since(leastDate) < keyExpiration {
		return "", fmt.Errorf("Not expired lastUsed:%s, accessKey:%s", leastDate, leastKey)
	}
	daParams := &iam.DeleteAccessKeyInput{
		AccessKeyId: leastKey.AccessKeyId,
		UserName:    leastKey.UserName,
	}
	daResp, err := svc.DeleteAccessKey(daParams)
	if err != nil {
		return "", err
	}
	return daResp.String(), nil
	//log.Printf("leastkey:%v", leastKey)
	//log.Printf("dryrun delete :%v", daParams)
	return "", nil

}
