# OpenEFA Troubleshooting Guide

Common issues and solutions for OpenEFA Email Security System.

## Installation Issues

### Pre-Flight Check Failures

**Issue**: Insufficient RAM/Disk/CPU

```bash
# Check system resources
free -h
df -h /opt
nproc
```

**Solution**: Upgrade server resources or choose Tier 1 (minimal) installation

---

**Issue**: Port 25 already in use

```bash
# Check what's using port 25
sudo ss -tulnp | grep :25
```

**Solution**: 
- If Postfix running: Installer will reconfigure
- If other MTA: Remove or disable before installation

---

**Issue**: Database server already running

**Solution**: Installer will use existing MariaDB/MySQL instance

---

### Installation Failures

**Issue**: Package installation failed

```bash
# Check internet connectivity
ping -c 3 google.com

# Update package lists
sudo apt update

# Retry installation
sudo bash install.sh
```

---

**Issue**: Python package installation failed

**Solution**:
```bash
# Update pip
/opt/spacyserver/venv/bin/pip install --upgrade pip

# Reinstall failed package manually
/opt/spacyserver/venv/bin/pip install package-name
```

---

**Issue**: Database schema import failed

**Solution**:
```bash
# Check MariaDB is running
sudo systemctl status mariadb

# Check log file
sudo tail -100 /var/log/openefa_install.log

# Manual schema import
sudo -u root mysql spacy_email_db < /opt/spacyserver/installer/sql/schema_v1.sql
```

---

## Email Flow Issues

### Emails Not Being Received

**Symptoms**: No emails arriving at OpenEFA

**Diagnosis**:
```bash
# Check Postfix is running
sudo systemctl status postfix

# Check port 25 is listening
sudo ss -tuln | grep :25

# Test SMTP connection
telnet localhost 25

# Check MX records
dig MX yourdomain.com

# Check logs
sudo tail -f /var/log/mail.log
```

**Solutions**:
1. Verify DNS MX records point to OpenEFA
2. Check firewall allows port 25 inbound
3. Verify Postfix configuration: `sudo postconf | grep mydestination`
4. Restart Postfix: `sudo systemctl restart postfix`

---

### Emails Not Being Relayed

**Symptoms**: Emails stuck in queue, not forwarded to destination

**Diagnosis**:
```bash
# Check mail queue
mailq

# Check Postfix transport maps
sudo postmap -q yourdomain.com /etc/postfix/transport

# Test relay connectivity
telnet destination-server-ip 25

# Check logs
sudo grep "status=bounced" /var/log/mail.log
```

**Solutions**:
1. Verify transport maps configured correctly
2. Verify destination server IP is correct
3. Check network connectivity to relay server
4. Check relay server accepts mail from OpenEFA IP

---

### Email Filter Crashes (Status 120)

**Symptoms**: `Command died with status 120` in mail.log

**Diagnosis**:
```bash
# Check email filter logs
sudo tail -100 /opt/spacyserver/logs/email_filter_error.log

# Check for Python errors
sudo grep -i "error\|exception" /opt/spacyserver/logs/email_filter_error.log

# Test email filter manually
sudo -u spacy-filter /opt/spacyserver/email_filter.py sender@example.com recipient@yourdomain.com < /path/to/test/email.eml
```

**Solutions**:
1. Check for missing Python modules
2. Verify database connectivity
3. Check email_filter.py permissions (755, owned by spacy-filter)
4. Disable problematic modules in module_config.json
5. Increase timeout: `sudo postconf -e "command_time_limit=300s"`

---

## Service Issues

### Database Processor Not Starting

**Symptoms**: `spacy-db-processor` service fails to start

**Diagnosis**:
```bash
# Check service status
sudo systemctl status spacy-db-processor

# View logs
sudo journalctl -u spacy-db-processor -n 100

# Check database connectivity
sudo -u spacy-filter mysql --defaults-file=/opt/spacyserver/config/.my.cnf -e "SELECT 1;"

# Check Redis
redis-cli ping
```

**Solutions**:
1. Verify MariaDB is running: `sudo systemctl start mariadb`
2. Verify Redis is running: `sudo systemctl start redis-server`
3. Check .my.cnf credentials: `/opt/spacyserver/config/.my.cnf`
4. Check Python environment: `/opt/spacyserver/venv/bin/python3 --version`
5. Restart service: `sudo systemctl restart spacy-db-processor`

---

### SpacyWeb Not Accessible

**Symptoms**: Cannot access https://server:5500

**Diagnosis**:
```bash
# Check service status
sudo systemctl status spacyweb

# Check if port is listening
sudo ss -tuln | grep :5500

# View logs
sudo journalctl -u spacyweb -n 50

# Test locally
curl -k https://localhost:5500
```

**Solutions**:
1. Verify service is running: `sudo systemctl start spacyweb`
2. Check firewall: `sudo ufw allow 5500/tcp`
3. Verify SSL certificate exists: `ls -l /etc/ssl/certs/ssl-cert-snakeoil.pem`
4. Check app.py for errors: `sudo journalctl -u spacyweb -n 100 | grep -i error`

---

## Performance Issues

### High CPU Usage

**Diagnosis**:
```bash
# Check CPU usage
htop

# Check which services are consuming CPU
ps aux --sort=-%cpu | head -10

# Check email queue size
mailq | tail -1
```

**Solutions**:
1. Reduce Postfix maxproc: `sudo postconf -e "default_process_limit=50"`
2. Disable resource-intensive modules (NER, PDF analyzer)
3. Lower module tier: Edit `/opt/spacyserver/config/module_config.json`
4. Increase server resources

---

### High Memory Usage

**Diagnosis**:
```bash
# Check memory
free -h

# Check process memory usage
ps aux --sort=-%mem | head -10
```

**Solutions**:
1. Restart services to clear caches
2. Disable SpaCy NLP modules (if Tier 3)
3. Adjust Python garbage collection
4. Increase server RAM

---

### Slow Email Processing

**Diagnosis**:
```bash
# Check queue delays
mailq

# Check filter processing time
sudo grep "Processing time" /opt/spacyserver/logs/email_filter_debug.log

# Check Redis queue depth
redis-cli LLEN email_queue
```

**Solutions**:
1. Enable adaptive processing
2. Reduce module tier
3. Increase Postfix concurrency limits
4. Scale horizontally (multiple OpenEFA servers)

---

## Database Issues

### Database Connection Errors

**Symptoms**: "Can't connect to MySQL server"

**Diagnosis**:
```bash
# Check MariaDB is running
sudo systemctl status mariadb

# Test connection
sudo -u spacy-filter mysql --defaults-file=/opt/spacyserver/config/.my.cnf -e "SELECT 1;"

# Check credentials
sudo cat /opt/spacyserver/config/.my.cnf
```

**Solutions**:
1. Start MariaDB: `sudo systemctl start mariadb`
2. Verify credentials in .my.cnf
3. Reset database password if forgotten
4. Check disk space: `df -h`

---

### Database Disk Full

**Symptoms**: "No space left on device"

**Diagnosis**:
```bash
# Check disk usage
df -h

# Check database size
sudo du -sh /var/lib/mysql/
```

**Solutions**:
1. Clean up old logs
2. Purge old email records
3. Enable automatic cleanup
4. Increase disk space

---

## Module-Specific Issues

### RBL Lookups Failing

**Diagnosis**:
```bash
# Test DNS resolution
dig +short 2.0.0.127.zen.spamhaus.org

# Check RBL config
cat /opt/spacyserver/config/rbl_config.json
```

**Solutions**:
1. Verify DNS resolver is working
2. Check RBL services are not blocking your IP
3. Increase timeout in rbl_config.json
4. Use alternative RBL lists

---

### Conversation Learning Not Working

**Diagnosis**:
```bash
# Check learning stats
sudo -u spacy-filter mysql --defaults-file=/opt/spacyserver/config/.my.cnf spacy_email_db -e "SELECT * FROM conversation_learning_stats;"

# Check configuration
cat /opt/spacyserver/config/conversation_learning_config.json
```

**Solutions**:
1. Verify learning is enabled in config
2. Ensure sufficient training data (low spam score emails)
3. Adjust learning threshold
4. Manually feed legitimate emails

---

## Log Analysis

### Key Log Files

```bash
# Email flow
/var/log/mail.log

# Email filter
/opt/spacyserver/logs/email_filter_error.log
/opt/spacyserver/logs/email_filter_debug.log

# Database processor
/opt/spacyserver/logs/db_processor.log

# Services
journalctl -u spacy-db-processor
journalctl -u spacyweb
journalctl -u postfix
```

### Common Log Patterns

**Successful processing**:
```
email_filter.py: Email processed successfully
postfix/smtp: status=sent
```

**Authentication failure**:
```
SPF check failed
DKIM verification failed
DMARC failed
```

**Filter crash**:
```
Command died with status 120
FATAL ERROR
UnboundLocalError
```

**Database issues**:
```
Can't connect to MySQL
Lost connection to MySQL
Redis connection error
```

---

## Getting Help

### Information to Provide

When requesting support, provide:

1. **System Info**:
```bash
lsb_release -a
free -h
df -h
```

2. **OpenEFA Version**:
```bash
cat /opt/spacyserver/VERSION
```

3. **Service Status**:
```bash
sudo systemctl status postfix spacy-db-processor spacyweb
```

4. **Recent Logs**:
```bash
sudo tail -100 /var/log/mail.log
sudo tail -100 /opt/spacyserver/logs/email_filter_error.log
```

5. **Error Messages**: Copy exact error text

### Support Channels

- **Community Forum**: https://forum.openefa.com
- **GitHub Issues**: https://github.com/openefaadmin/openefa/issues
- **Documentation**: https://docs.openefa.com

---

## Emergency Rollback

If system is unstable after installation:

```bash
# Complete uninstall
sudo /opt/spacyserver/installer/uninstall.sh

# Restore Postfix config from backup
sudo cp /etc/postfix/backup_*/main.cf /etc/postfix/
sudo systemctl restart postfix
```

---

## Advanced Debugging

### Enable Debug Mode

```bash
# Enable debug logging
/opt/spacyserver/switch_to_debug.sh

# Monitor real-time
/opt/spacyserver/scripts/live_email_monitor.sh
```

### Trace Email Processing

```bash
# Find email by ID
sudo grep "MESSAGE_ID" /var/log/mail.log

# Check email database entry
sudo -u spacy-filter mysql --defaults-file=/opt/spacyserver/config/.my.cnf spacy_email_db \
  -e "SELECT * FROM emails WHERE message_id='MESSAGE_ID'\\G"
```

### Module Testing

```bash
# Test individual modules
cd /opt/spacyserver
./test_bec_typosquatting.py
./test_cn_blocking.py
./test_ner_integration.py
```
