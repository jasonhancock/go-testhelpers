package redis

import (
	"testing"

	"github.com/gomodule/redigo/redis"
	"github.com/stretchr/testify/require"
)

const db = 15

// Setup creates a new Redis pool. It connects to a Redis server and clears out the DB
// first before returning the connection pool.
func Setup(t *testing.T) *redis.Pool {
	pool := &redis.Pool{
		// Other pool configuration not shown in this example.
		Dial: func() (redis.Conn, error) {
			c, err := redis.Dial("tcp", ":6379")
			if err != nil {
				return nil, err
			}
			if _, err := c.Do("SELECT", db); err != nil {
				require.NoError(t, c.Close())
				return nil, err
			}
			return c, nil
		},
	}

	conn := pool.Get()
	defer conn.Close()

	t.Cleanup(func() {
		require.NoError(t, pool.Close())
	})

	_, err := conn.Do("FLUSHDB")
	require.NoError(t, err)
	return pool
}
