package store

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	"github.com/sriramg-aivar/CodeSentinal./internal/types"
)

// Dynamo persists reviews to a single DynamoDB table.
//
// Item schema (string attributes):
//
//	pk        = "REVIEW"             (constant partition for listing)
//	sk        = "<created_at_rfc3339nano>#<review_id>"  (sort, newest last)
//	review_id = <uuid>
//	body      = <json of the PostureReview>
//
// Listing recent reviews = Query pk="REVIEW" ScanIndexForward=false.
// Get-by-id uses a secondary item pk="REVIEW#<id>".
type Dynamo struct {
	c     *dynamodb.Client
	table string
}

const reviewPK = "REVIEW"

func NewDynamo(c *dynamodb.Client, table string) *Dynamo {
	return &Dynamo{c: c, table: table}
}

func (d *Dynamo) Kind() string { return "dynamodb:" + d.table }

const chunkLimit = 300 * 1024 // 300 KB per item

func (d *Dynamo) Put(ctx context.Context, r *types.PostureReview) error {
	body, err := json.Marshal(r)
	if err != nil {
		return err
	}
	sk := r.CreatedAt.UTC().Format("2006-01-02T15:04:05.000000000Z") + "#" + r.ReviewID

	if len(body) <= chunkLimit {
		// small review: store whole body in both the list and get items
		for _, it := range []map[string]ddbtypes.AttributeValue{
			{"pk": s(reviewPK), "sk": s(sk), "review_id": s(r.ReviewID), "body": s(string(body))},
			{"pk": s(reviewPK + "#" + r.ReviewID), "sk": s("-"), "body": s(string(body))},
		} {
			if _, err := d.c.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(d.table), Item: it}); err != nil {
				return fmt.Errorf("put item: %w", err)
			}
		}
		return nil
	}

	// large review: store a summary (without findings/resources) plus chunks.
	summary := *r
	summary.Findings = nil
	summary.Resources = nil
	summary.Paths = nil
	sumBody, _ := json.Marshal(&summary)
	heavy, _ := json.Marshal(map[string]any{
		"findings": r.Findings, "resources": r.Resources, "paths": r.Paths,
	})
	chunks := splitChunks(heavy, chunkLimit)

	item := func(pk, sk string, extra map[string]ddbtypes.AttributeValue) map[string]ddbtypes.AttributeValue {
		m := map[string]ddbtypes.AttributeValue{"pk": s(pk), "sk": s(sk)}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	// list item (summary only, for history/listing)
	if _, err := d.c.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(d.table),
		Item: item(reviewPK, sk, map[string]ddbtypes.AttributeValue{"review_id": s(r.ReviewID), "body": s(string(sumBody)), "chunked": s("true")})}); err != nil {
		return fmt.Errorf("put list item: %w", err)
	}
	// get summary item
	base := reviewPK + "#" + r.ReviewID
	if _, err := d.c.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(d.table),
		Item: item(base, "-", map[string]ddbtypes.AttributeValue{"body": s(string(sumBody)), "chunked": s("true"), "nchunks": n(len(chunks))})}); err != nil {
		return fmt.Errorf("put summary: %w", err)
	}
	for i, c := range chunks {
		csk := fmt.Sprintf("chunk#%04d", i)
		if _, err := d.c.PutItem(ctx, &dynamodb.PutItemInput{TableName: aws.String(d.table),
			Item: item(base, csk, map[string]ddbtypes.AttributeValue{"body": s(string(c))})}); err != nil {
			return fmt.Errorf("put chunk %d: %w", i, err)
		}
	}
	return nil
}

func s(v string) *ddbtypes.AttributeValueMemberS { return &ddbtypes.AttributeValueMemberS{Value: v} }
func n(i int) *ddbtypes.AttributeValueMemberN {
	return &ddbtypes.AttributeValueMemberN{Value: fmt.Sprintf("%d", i)}
}

func splitChunks(b []byte, size int) [][]byte {
	var out [][]byte
	for len(b) > size {
		out = append(out, b[:size])
		b = b[size:]
	}
	out = append(out, b)
	return out
}

func (d *Dynamo) Get(ctx context.Context, id string) (*types.PostureReview, error) {
	base := reviewPK + "#" + id
	out, err := d.c.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(d.table),
		Key:       map[string]ddbtypes.AttributeValue{"pk": s(base), "sk": s("-")},
	})
	if err != nil {
		return nil, err
	}
	if out.Item == nil {
		return nil, nil
	}
	rv, err := decodeBody(out.Item)
	if err != nil || rv == nil {
		return rv, err
	}
	// reassemble chunks if present
	if c, ok := out.Item["chunked"].(*ddbtypes.AttributeValueMemberS); ok && c.Value == "true" {
		q, err := d.c.Query(ctx, &dynamodb.QueryInput{
			TableName:              aws.String(d.table),
			KeyConditionExpression: aws.String("pk = :pk AND begins_with(sk, :p)"),
			ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
				":pk": s(base), ":p": s("chunk#"),
			},
			ScanIndexForward: aws.Bool(true),
		})
		if err != nil {
			return nil, err
		}
		var buf strings.Builder
		for _, it := range q.Items {
			if b, ok := it["body"].(*ddbtypes.AttributeValueMemberS); ok {
				buf.WriteString(b.Value)
			}
		}
		var heavy struct {
			Findings  []types.Finding    `json:"findings"`
			Resources []types.Resource   `json:"resources"`
			Paths     []types.AttackPath `json:"paths"`
		}
		if err := json.Unmarshal([]byte(buf.String()), &heavy); err == nil {
			rv.Findings = heavy.Findings
			rv.Resources = heavy.Resources
			rv.Paths = heavy.Paths
		}
	}
	return rv, nil
}

func (d *Dynamo) Latest(ctx context.Context) (*types.PostureReview, error) {
	out, err := d.c.Query(ctx, &dynamodb.QueryInput{
		TableName:                 aws.String(d.table),
		KeyConditionExpression:    aws.String("pk = :pk"),
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{":pk": s(reviewPK)},
		ScanIndexForward:          aws.Bool(false),
		Limit:                     aws.Int32(1),
	})
	if err != nil || len(out.Items) == 0 {
		return nil, err
	}
	it := out.Items[0]
	// if chunked, fetch the full review by id
	if c, ok := it["chunked"].(*ddbtypes.AttributeValueMemberS); ok && c.Value == "true" {
		if rid, ok := it["review_id"].(*ddbtypes.AttributeValueMemberS); ok {
			return d.Get(ctx, rid.Value)
		}
	}
	return decodeBody(it)
}

func (d *Dynamo) List(ctx context.Context, limit int) ([]*types.PostureReview, error) {
	var lim *int32
	if limit > 0 {
		l := int32(limit)
		lim = &l
	}
	out, err := d.c.Query(ctx, &dynamodb.QueryInput{
		TableName:              aws.String(d.table),
		KeyConditionExpression: aws.String("pk = :pk"),
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{
			":pk": &ddbtypes.AttributeValueMemberS{Value: reviewPK},
		},
		ScanIndexForward: aws.Bool(false), // newest first
		Limit:            lim,
	})
	if err != nil {
		return nil, err
	}
	var reviews []*types.PostureReview
	for _, it := range out.Items {
		r, err := decodeBody(it)
		if err != nil || r == nil {
			continue
		}
		reviews = append(reviews, r)
	}
	sort.SliceStable(reviews, func(i, j int) bool {
		return reviews[i].CreatedAt.After(reviews[j].CreatedAt)
	})
	return reviews, nil
}

func decodeBody(item map[string]ddbtypes.AttributeValue) (*types.PostureReview, error) {
	bodyAttr, ok := item["body"].(*ddbtypes.AttributeValueMemberS)
	if !ok {
		return nil, nil
	}
	var r types.PostureReview
	if err := json.Unmarshal([]byte(bodyAttr.Value), &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ---- Dynamo KV ----

func (d *Dynamo) KV() KV { return &dynamoKV{c: d.c, table: d.table} }

type dynamoKV struct {
	c     *dynamodb.Client
	table string
}

// kvPK namespaces KV partitions so they never collide with REVIEW items.
func kvPK(pk string) string { return "KV#" + pk }

func (k *dynamoKV) PutItem(ctx context.Context, pk, sk string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = k.c.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(k.table),
		Item:      map[string]ddbtypes.AttributeValue{"pk": s(kvPK(pk)), "sk": s(sk), "body": s(string(b))},
	})
	return err
}

func (k *dynamoKV) GetItem(ctx context.Context, pk, sk string, out any) (bool, error) {
	o, err := k.c.GetItem(ctx, &dynamodb.GetItemInput{
		TableName: aws.String(k.table),
		Key:       map[string]ddbtypes.AttributeValue{"pk": s(kvPK(pk)), "sk": s(sk)},
	})
	if err != nil {
		return false, err
	}
	if o.Item == nil {
		return false, nil
	}
	b, ok := o.Item["body"].(*ddbtypes.AttributeValueMemberS)
	if !ok {
		return false, nil
	}
	return true, json.Unmarshal([]byte(b.Value), out)
}

func (k *dynamoKV) Query(ctx context.Context, pk, skPrefix string, limit int, newestFirst bool, out any) error {
	in := &dynamodb.QueryInput{
		TableName:                 aws.String(k.table),
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{":pk": s(kvPK(pk))},
		ScanIndexForward:          aws.Bool(!newestFirst),
	}
	if skPrefix != "" {
		in.KeyConditionExpression = aws.String("pk = :pk AND begins_with(sk, :p)")
		in.ExpressionAttributeValues[":p"] = s(skPrefix)
	} else {
		in.KeyConditionExpression = aws.String("pk = :pk")
	}
	if limit > 0 {
		in.Limit = aws.Int32(int32(limit))
	}
	o, err := k.c.Query(ctx, in)
	if err != nil {
		return err
	}
	arr := make([]json.RawMessage, 0, len(o.Items))
	for _, it := range o.Items {
		if b, ok := it["body"].(*ddbtypes.AttributeValueMemberS); ok {
			arr = append(arr, json.RawMessage(b.Value))
		}
	}
	joined, _ := json.Marshal(arr)
	return json.Unmarshal(joined, out)
}

func (k *dynamoKV) DeleteItem(ctx context.Context, pk, sk string) error {
	_, err := k.c.DeleteItem(ctx, &dynamodb.DeleteItemInput{
		TableName: aws.String(k.table),
		Key:       map[string]ddbtypes.AttributeValue{"pk": s(kvPK(pk)), "sk": s(sk)},
	})
	return err
}

func (k *dynamoKV) AcquireLease(ctx context.Context, name, owner string, ttl time.Duration) (bool, error) {
	now := time.Now()
	exp := now.Add(ttl)
	_, err := k.c.PutItem(ctx, &dynamodb.PutItemInput{
		TableName: aws.String(k.table),
		Item: map[string]ddbtypes.AttributeValue{
			"pk": s(kvPK("lease")), "sk": s(name), "owner": s(owner), "expires_at": n(int(exp.Unix())),
		},
		ConditionExpression:       aws.String("attribute_not_exists(pk) OR expires_at < :now OR #o = :owner"),
		ExpressionAttributeNames:  map[string]string{"#o": "owner"},
		ExpressionAttributeValues: map[string]ddbtypes.AttributeValue{":now": n(int(now.Unix())), ":owner": s(owner)},
	})
	if err != nil {
		if strings.Contains(err.Error(), "ConditionalCheckFailed") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// avoid unused import if sort ever drops out
var _ = sort.SliceStable
