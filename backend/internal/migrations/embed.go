// Package migrations 只负责把 SQL 迁移文件嵌进二进制，避免部署时漏拷文件。
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
