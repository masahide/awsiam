package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/iam"
)

type stab struct {
	lastusedDate map[string]time.Time
	username     string
}

var stabData = stab{
	lastusedDate: map[string]time.Time{
		"testid1": time.Now().Add(-24 * 3 * time.Hour),
		"testid2": time.Now().Add(-24 * 4 * time.Hour),
	},
	username: "hoge",
}

func (s *stab) GetAccessKeyLastUsed(input *iam.GetAccessKeyLastUsedInput) (*iam.GetAccessKeyLastUsedOutput, error) {
	t := s.lastusedDate[*input.AccessKeyId]
	return &iam.GetAccessKeyLastUsedOutput{
		AccessKeyLastUsed: &iam.AccessKeyLastUsed{LastUsedDate: &t},
		UserName:          &s.username,
	}, nil
}

func (s *stab) ListAccessKeys(input *iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
	return &iam.ListAccessKeysOutput{
		AccessKeyMetadata: []*iam.AccessKeyMetadata{
			&iam.AccessKeyMetadata{
				AccessKeyId: aws.String("testid1"),
				CreateDate:  aws.Time(time.Now().Add(-24 * time.Hour)),
			},
			&iam.AccessKeyMetadata{
				AccessKeyId: aws.String("testid2"),
				CreateDate:  aws.Time(time.Now().Add(-24 * 2 * time.Hour)),
			},
		},
	}, nil

}
func (s *stab) CreateUser(input *iam.CreateUserInput) (*iam.CreateUserOutput, error) {
	return &iam.CreateUserOutput{User: &iam.User{UserName: aws.String("user1")}}, nil
}
func (s *stab) DeleteUser(input *iam.DeleteUserInput) (*iam.DeleteUserOutput, error) {
	return &iam.DeleteUserOutput{}, nil
}
func (s *stab) CreateAccessKey(input *iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
	return &iam.CreateAccessKeyOutput{}, nil
}
func (s *stab) DeleteAccessKey(input *iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error) {
	return &iam.DeleteAccessKeyOutput{}, nil
}

func TestNilString(t *testing.T) {
	res := nilString("")
	if res != nil {
		t.Errorf("want:nil res:%v", res)
	}
	res = nilString("hoge")
	if *res != "hoge" {
		t.Errorf("want:hoge res:%v", *res)
	}
}

type testError struct {
	error
}

func (t testError) Code() string    { return "code" }
func (t testError) Message() string { return "message" }
func (t testError) OrigErr() error  { return fmt.Errorf("%s", "error") }

func TestIsAwsErr(t *testing.T) {
	err := testError{}
	if !isAwsErr("code", err) {
		t.Errorf("want true %s", err.Code())
	}
	if isAwsErr("hoge", err) {
		t.Errorf("want false %s", err.Code())
	}
}

func TestGetLastUseds(t *testing.T) {
	a := &awsiam{svc: &stabData}
	data := []*iam.AccessKeyMetadata{
		&iam.AccessKeyMetadata{
			AccessKeyId: aws.String("testid1"),
			CreateDate:  aws.Time(time.Now().Add(-24 * time.Hour)),
		},
		&iam.AccessKeyMetadata{
			AccessKeyId: aws.String("testid2"),
			CreateDate:  aws.Time(time.Now().Add(-24 * 2 * time.Hour)),
		},
	}
	keys, err := a.getLastUseds(data)
	l := len(keys)
	if err != nil {
		t.Errorf("want:nil,get:%v", err)
	}
	if l != 2 {
		t.Errorf("want:2,get:%v", l)
	}
	if *keys[0].AccessKeyId != "testid1" {
		t.Errorf("want:testid1,get:%v", keys[0])
	}
	if *keys[1].AccessKeyId != "testid2" {
		t.Errorf("want:testid2,get:%v", keys[1])
	}
	//log.Print(keys)
}
