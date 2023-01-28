
# Fix Corrupted RPM Database

## Backup
```
mkdir ~/backups/
tar -zcvf ~/backups/rpmdb-$(date +"%d%m%Y").tar.gz  /var/lib/rpm
```

## Delete DB
```
rm -f /var/lib/rpm/__db*	
```

## Verify DB
```
/usr/lib/rpm/rpmdb_verify /var/lib/rpm/Packages
```

## If DB Passes Validation
```
cd /var/lib/rpm/
mv Packages Packages.bkup
/usr/lib/rpm/rpmdb_dump Packages.bkup | /usr/lib/rpm/rpmdb_load Packages
/usr/lib/rpm/rpmdb_verify Packages
```

## If DB Fails Validation 
This will cause error messages on key system Packages.  Add/Remove Packages as needed to allow yum to rebuild 
```
# Obtain /var/lib/rpm/Packages from a similar system and place it in users home path

cd /var/lib/rpm/
mv Packages Packages.bkup
/usr/lib/rpm/rpmdb_dump /home/<user>/Packages | /usr/lib/rpm/rpmdb_load Packages
/usr/lib/rpm/rpmdb_verify Packages
```

## Rebuild DB
```
rpm -vv --rebuilddb
```

## Query RPM
```
# this will generate lengthy output

rpm -qa
```

## Update YUM
```
yum check-update
```
