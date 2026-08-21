#!/bin/bash
BACKUP_DIR=/var/backups/dfim
DATE=$(date +%Y%m%d_%H%M)
su -l postgres -c "pg_dump dfim_production | gzip > $BACKUP_DIR/dfim_$DATE.sql.gz"
find $BACKUP_DIR -name "*.sql.gz" -mtime +7 -delete 2>/dev/null
echo "dfim_$DATE.sql.gz"
