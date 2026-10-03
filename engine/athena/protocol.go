package athena

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func executeSQL(ctx context.Context, client *http.Client, endpoint string, request Request, user string, consume func(Page) error) error {
	sql := request.SQL
	if len(request.Parameters) != 0 {
		// Trino parses parameters itself; no SQL interpretation or interpolation
		// is performed by the adapter.
		sql = "EXECUTE IMMEDIATE '" + strings.ReplaceAll(sql, "'", "''") + "' USING " + strings.Join(request.Parameters, ", ")
	}
	headers := make(http.Header)
	headers.Set("X-Trino-User", user)
	headers.Set("X-Trino-Source", "stackd-athena")
	headers.Set("X-Trino-Time-Zone", "UTC")
	headers.Set("X-Trino-Catalog", request.Catalog)
	if request.Database != "" {
		headers.Set("X-Trino-Schema", request.Database)
	}
	names := make([]string, 0, len(request.PreparedStatements))
	for name := range request.PreparedStatements {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		headers.Add("X-Trino-Prepared-Statement", url.QueryEscape(name)+"="+url.QueryEscape(request.PreparedStatements[name]))
	}
	next := endpoint + "/v1/statement"
	method := http.MethodPost
	var body io.Reader = strings.NewReader(sql)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, method, next, body)
		if err != nil {
			return err
		}
		req.Header = headers
		response, err := client.Do(req)
		if err != nil {
			return err
		}
		if response.StatusCode != http.StatusOK {
			data, readErr := io.ReadAll(io.LimitReader(response.Body, 8192))
			response.Body.Close()
			return errors.Join(fmt.Errorf("trino HTTP %d: %s", response.StatusCode, data), readErr)
		}
		var page Page
		err = json.NewDecoder(response.Body).Decode(&page)
		response.Body.Close()
		if err != nil {
			return fmt.Errorf("decode Trino result: %w", err)
		}
		if page.NextURI == "" || page.Error != nil {
			var queryErr error
			if page.Error != nil {
				queryErr = page.Error
			}
			// QueryInfo retains the native parser's classification even when
			// analysis fails. Never classify arbitrary SQL using string prefixes.
			infoReq, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/v1/query/"+url.PathEscape(page.ID), nil)
			if reqErr != nil {
				return reqErr
			}
			infoReq.Header = headers
			infoResponse, infoErr := client.Do(infoReq)
			if infoErr != nil {
				return errors.Join(queryErr, infoErr)
			}
			var info struct {
				QueryType string `json:"queryType"`
			}
			if infoResponse.StatusCode != http.StatusOK {
				infoResponse.Body.Close()
				return errors.Join(queryErr, fmt.Errorf("trino query information HTTP %d", infoResponse.StatusCode))
			}
			infoErr = json.NewDecoder(infoResponse.Body).Decode(&info)
			infoResponse.Body.Close()
			if infoErr != nil {
				return errors.Join(queryErr, infoErr)
			}
			page.QueryType = info.QueryType
		}
		if page.NextURI != "" {
			// Only the owned coordinator can supply result pages. Never follow a
			// native URL to another host or public AWS endpoint.
			parsed, parseErr := url.Parse(page.NextURI)
			origin, _ := url.Parse(endpoint)
			if parseErr != nil || parsed.Scheme != origin.Scheme || parsed.Host != origin.Host || parsed.User != nil || !strings.HasPrefix(parsed.Path, "/v1/statement/") {
				return errors.New("trino returned a result URL outside the owned coordinator")
			}
		}
		if err := consume(page); err != nil {
			if page.NextURI != "" {
				cancelCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				cancelReq, _ := http.NewRequestWithContext(cancelCtx, http.MethodDelete, page.NextURI, nil)
				if response, cancelErr := client.Do(cancelReq); cancelErr == nil {
					response.Body.Close()
				}
				cancel()
			}
			return err
		}
		if page.Error != nil {
			return page.Error
		}
		if page.NextURI == "" {
			return nil
		}
		method, next, body = http.MethodGet, page.NextURI, nil
	}
}
