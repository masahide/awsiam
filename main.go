package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
)

const (
	entityAlreadyExists = "EntityAlreadyExists"
	limitExceeded       = "LimitExceeded"
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
	addGroupName    = "infra-common,infra-read-only"
)

func init() {
	flag.BoolVar(&showResult, "show", showResult, "show result")
	flag.StringVar(&user, "addUser", user, "add user name")
	flag.StringVar(&addGroupName, "group", addGroupName, "add group names")
	flag.StringVar(&roleArn, "assumeRole", roleArn, "role arn Ex:'arn:aws:iam::123456789012:role/role-name'")
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
		a := &awsiam{svc: iam.New(sess)}
		res, err = a.addUser(user)
		if err != nil {
			log.Fatal(err)
		}
	}
	if showResult {
		fmt.Println(res)
	}
}

type iamsvc interface {
	GetAccessKeyLastUsed(input *iam.GetAccessKeyLastUsedInput) (*iam.GetAccessKeyLastUsedOutput, error)
	ListAccessKeys(input *iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error)
	CreateUser(input *iam.CreateUserInput) (*iam.CreateUserOutput, error)
	DeleteUser(input *iam.DeleteUserInput) (*iam.DeleteUserOutput, error)
	CreateAccessKey(input *iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error)
	DeleteAccessKey(input *iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error)
	ListGroupsForUser(input *iam.ListGroupsForUserInput) (*iam.ListGroupsForUserOutput, error)
}

type awsiam struct {
	svc iamsvc
}

func (a *awsiam) addUser(username string) (string, error) {
	res := ""
	cuParams := &iam.CreateUserInput{UserName: aws.String(user)}
	cuResp, err := a.svc.CreateUser(cuParams)
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
	cakResp, err := a.svc.CreateAccessKey(cakParams)
	if isAwsErr(limitExceeded, err) {
		if !skipCreate {
			return res, err
		}
		err = nil
		res = "Cannot exceed quota for AccessKeysPerUser: n"
	} else if err != nil {
		return res, err
	} else {
		res += "\n" + cakResp.String()
		return res, nil
	}

	keys, err := a.getAccessKeys(username)
	if err != nil {
		return res, err
	}
	//log.Print(keys)
	//for i := range keys {
	//	log.Printf("%# v\n", keys[i].AccessKeyMetadata)
	//	log.Printf("%v\n", keys[i].lastUsed)
	//}
	oldest := oldestUsedKey(keys)
	if isExpired(oldest, keyExpiration) {
		return res, fmt.Errorf("Not expired lastUsed: %s", oldest)
	}
	daParams := &iam.DeleteAccessKeyInput{AccessKeyId: oldest.AccessKeyId, UserName: oldest.UserName}
	daRes, err := a.svc.DeleteAccessKey(daParams)
	if err != nil {
		return "", err
	}
	res += "\n" + daRes.String()
	cakResp, err = a.svc.CreateAccessKey(cakParams)
	if err != nil {
		return res, err
	}
	res += "\n" + cakResp.String()
	return res, err
}

func isAwsErr(code string, err error) bool {
	if awsErr, ok := err.(awserr.Error); ok {
		//log.Println("error code():", awsErr.Code())
		if awsErr.Code() == code {
			return true
		}
	}
	return false
}

type accessKey struct {
	lastUsed time.Time
	iam.AccessKeyMetadata
}

func (a accessKey) String() string {
	return fmt.Sprintf("{ID:%s CreateAt:%s lastUsed:%s}", *a.AccessKeyId, *a.CreateDate, a.lastUsed)
}

func (a *awsiam) getLastUseds(keys []*iam.AccessKeyMetadata) ([]accessKey, error) {
	res := make([]accessKey, len(keys))
	for id, key := range keys {
		res[id].AccessKeyMetadata = *key
		res[id].lastUsed = *key.CreateDate
		luParams := &iam.GetAccessKeyLastUsedInput{AccessKeyId: key.AccessKeyId}
		resp, err := a.svc.GetAccessKeyLastUsed(luParams)
		if err != nil {
			return res, err
		}
		if resp.AccessKeyLastUsed != nil && resp.AccessKeyLastUsed.LastUsedDate != nil {
			res[id].lastUsed = *resp.AccessKeyLastUsed.LastUsedDate
		}
	}
	return res, nil
}

func (a *awsiam) getGroups(username string) ([]string, error) {
	params := &iam.ListGroupsForUserInput{UserName: aws.String(username)}
	resp, err := a.svc.ListGroupsForUser(params)
	if err != nil {
		return nil, err
	}
	if resp.Groups == nil {
		return nil, nil
	}
	res := make([]string, len(resp.Groups))
	for id, group := range resp.Groups {
		res[id] = *group.GroupName
	}
	return res, nil
}

func lackingGroup(getGroups []string) []string {
	addGroup := strings.Split(addGroupName, ",")
	res := make([]string, 0, len(addGroup))
	for _, addName := range addGroup {
		ok := false
	LBL1:
		for _, getName := range getGroups {
			if addName == getName {
				ok = true
				break LBL1
			}
		}
		if !ok {
			res = append(res, addName)
		}
	}
	return res
}

func (a *awsiam) getAccessKeys(username string) ([]accessKey, error) {
	params := &iam.ListAccessKeysInput{UserName: aws.String(username)}
	laResp, err := a.svc.ListAccessKeys(params)
	if err != nil {
		return nil, err
	}
	keys, err := a.getLastUseds(laResp.AccessKeyMetadata)
	if err != nil {
		return nil, err
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].lastUsed.UnixNano() < keys[j].lastUsed.UnixNano()
	})
	return keys, nil
}

func oldestUsedKey(keys []accessKey) accessKey { return keys[0] }
func newestUsedKey(keys []accessKey) accessKey { return keys[len(keys)-1] }
func isExpired(key accessKey, expiration time.Duration) bool {
	return time.Since(key.lastUsed) < expiration
}
