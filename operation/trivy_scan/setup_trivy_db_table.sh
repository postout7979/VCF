#!/bin/bash

DB_NAME="cve_db"
DB_USER="cve_user"
DB_PASS="cve_password123!"



echo "[Setup] Trivy 전체 데이터 저장을 위한 DB 스키마 생성 중..."

sudo mysql -u root -e "
CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

USE ${DB_NAME};

-- 1. 메인 스캔 이력 테이블 (Header)
CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    hostname VARCHAR(255) NOT NULL,
    ip_address VARCHAR(50),
    os_family VARCHAR(50),
    os_name VARCHAR(100),
    scan_date DATETIME NOT NULL,
    total_vulns INT DEFAULT 0,
    total_misconfs INT DEFAULT 0,
    total_secrets INT DEFAULT 0,
    INDEX idx_host_date (hostname, scan_date)
);

-- 2. 취약점 상세 테이블 (Vulnerabilities)
CREATE TABLE IF NOT EXISTS vuln_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT,
    cve_id VARCHAR(50),
    pkg_name VARCHAR(255),
    installed_ver VARCHAR(100),
    fixed_ver VARCHAR(100),
    severity VARCHAR(20),
    cvss_score FLOAT,
    title VARCHAR(500),
    description TEXT,
    primary_url TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- 3. 설정 오류 상세 테이블 (Misconfigurations)
CREATE TABLE IF NOT EXISTS misconf_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT,
    type VARCHAR(50),
    rule_id VARCHAR(100),
    severity VARCHAR(20),
    title VARCHAR(500),
    message TEXT,
    status VARCHAR(20),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- 4. 비밀 정보 노출 테이블 (Secrets)
CREATE TABLE IF NOT EXISTS secret_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT,
    rule_id VARCHAR(100),
    category VARCHAR(50),
    severity VARCHAR(20),
    title VARCHAR(255),
    file_path TEXT,
    start_line INT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- 5. 라이선스 정보 테이블 (Licenses)
CREATE TABLE IF NOT EXISTS license_results (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT,
    pkg_name VARCHAR(255),
    license_name VARCHAR(100),
    file_path TEXT,
    severity VARCHAR(20),
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- 권한 부여
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'%';
FLUSH PRIVILEGES;
"

echo "[Success] 모든 테이블 생성이 완료되었습니다."
