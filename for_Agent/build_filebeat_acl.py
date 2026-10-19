"""Apply the small Redis ACL patch to the exact Elastic Beats v8.19.23 source tree.

Build with Go 1.26.8 from the source root:
  python3 /path/to/for_Agent/build_filebeat_acl.py .
  go build -o /path/to/for_Agent/build/filebeat-acl-8.19.23-amd64 ./filebeat
"""

import pathlib
import sys


def replace(path: pathlib.Path, before: str, after: str) -> None:
    content = path.read_text()
    if content.count(before) != 1:
        raise RuntimeError(f"Unexpected Beats source at {path}: expected one matching block")
    path.write_text(content.replace(before, after))


source = pathlib.Path(sys.argv[1]).resolve()
redis_dir = source / "libbeat/outputs/redis"
if not (source / "go.mod").read_text().startswith("module github.com/elastic/beats/v7\n\ngo 1.26.8\n"):
    raise RuntimeError("Expected Elastic Beats v8.19.23 (Go 1.26.8) source")

replace(redis_dir / "config.go",
        '\tPassword    string                `config:"password"`',
        '\tUsername    string                `config:"username"`\n\tPassword    string                `config:"password"`')
replace(redis_dir / "config.go",
        '\treturn nil\n}',
        '\tif c.Username != "" && c.Password == "" {\n'
        '\t\treturn fmt.Errorf("redis username requires password")\n'
        '\t}\n\treturn nil\n}')
replace(redis_dir / "redis.go",
        '\t\tclient := newClient(conn, observer, rConfig.Timeout,\n\t\t\tpass, rConfig.Db, key, dataType, rConfig.Index, enc, beat.Logger)',
        '\t\tclient := newClient(conn, observer, rConfig.Timeout,\n\t\t\trConfig.Username, pass, rConfig.Db, key, dataType, rConfig.Index, enc, beat.Logger)')
replace(redis_dir / "client.go",
        '\tpassword string\n', '\tusername string\n\tpassword string\n')
replace(redis_dir / "client.go",
        '\tpass string,\n', '\tuser string, pass string,\n')
replace(redis_dir / "client.go",
        '\t\tpassword: pass,\n', '\t\tusername: user,\n\t\tpassword: pass,\n')
replace(redis_dir / "client.go",
        'initRedisConn(conn, c.password, c.db)', 'initRedisConn(conn, c.username, c.password, c.db)')
replace(redis_dir / "client.go",
        'func initRedisConn(c redis.Conn, pwd string, db int) error {\n\tif pwd != "" {\n\t\tif _, err := c.Do("AUTH", pwd); err != nil {\n\t\t\treturn err\n\t\t}\n\t}',
        'func initRedisConn(c redis.Conn, user, pwd string, db int) error {\n'
        '\tif user != "" && pwd == "" {\n'
        '\t\treturn fmt.Errorf("redis username requires password")\n'
        '\t}\n'
        '\tif pwd != "" {\n'
        '\t\tvar err error\n'
        '\t\tif user != "" {\n'
        '\t\t\t_, err = c.Do("AUTH", user, pwd)\n'
        '\t\t} else {\n'
        '\t\t\t_, err = c.Do("AUTH", pwd)\n'
        '\t\t}\n'
        '\t\tif err != nil {\n\t\t\treturn err\n\t\t}\n\t}')
print("Patched Redis output for AUTH username password")
