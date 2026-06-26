# Forensic Log Extraction & Database Auditing via SQL

**Analyst:** Kadiri Olumuyiwa  
**Date:** June 2026  
**Database Audited:** `organization_security_logs`  
**Primary Language:** Structured Query Language (SQL) / PostgreSQL  

---

## 1. Scenario Overview

Following a reported performance degradation on internal administrative portals, the Security Operations Center (SOC) initiated an automated audit of system access logs. As the investigating analyst, my objective was to query the relational database to uncover evidence of two potential security incidents:
1. Unauthorized **after-hours access** to administrative systems.
2. Automated **brute-force credential stuffing** originating from suspicious IP addresses.

---

## 2. Database Schema

The investigation utilized two primary relational tables within the database:

### Table: `log_in_attempts`
| Column Name | Data Type | Description |
| :--- | :--- | :--- |
| `event_id` | INT | Unique identifier for each login event |
| `username` | VARCHAR | Employee domain account account name |
| `login_date` | DATE | Date of the login attempt |
| `login_time` | TIME | Timestamp of the attempt (UTC) |
| `ip_address` | VARCHAR | Source IP address of the client device |
| `success` | BOOLEAN | `1` (Success) or `0` (Failure) |

### Table: `employees`
| Column Name | Data Type | Description |
| :--- | :--- | :--- |
| `employee_id` | INT | Unique employee identification number |
| `username` | VARCHAR | Employee domain account name |
| `department` | VARCHAR | Corporate business unit |
| `clearance_level` | INT | Authorized system access tier (1–5) |

---

## 3. Investigation Phase 1: Auditing After-Hours Logins

Corporate policy mandates that administrative portal maintenance must occur during standard operating hours (**06:00:00 to 18:00:00 UTC**). To isolate unsanctioned after-hours access, I executed the following query filtering for successful logins outside this window:

```sql
-- Retrieve all successful login events occurring outside standard operating hours
SELECT 
    event_id,
    username,
    login_date,
    login_time,
    ip_address
FROM 
    log_in_attempts
WHERE 
    success = 1 
    AND (login_time < '06:00:00' OR login_time > '18:00:00')
ORDER BY 
    login_time DESC;
