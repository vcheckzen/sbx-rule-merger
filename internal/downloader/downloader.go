package downloader

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

func FetchWithRetry(client *http.Client, url string, retries int) ([]byte, error) {
	var last error
	for i := 0; i <= retries; i++ {
		resp, err := client.Get(url)
		if err != nil {
			last = err
			time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
			continue
		}
		b, err := func() ([]byte, error) {
			defer resp.Body.Close()
			if resp.StatusCode < 200 || resp.StatusCode > 299 {
				return nil, fmt.Errorf("http status %s", resp.Status)
			}
			return io.ReadAll(resp.Body)
		}()
		if err == nil {
			return b, nil
		}
		last = err
		time.Sleep(time.Duration(i+1) * 500 * time.Millisecond)
	}
	return nil, last
}