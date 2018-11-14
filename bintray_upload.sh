#!/bin/bash

BINTRAY_URL=https://api.bintray.com
BINTRAY_ACCOUNT=mcafee
BINTRAY_REPO=mysql-audit-plugin
#BINTRAY_APIKEY=2df61574ec5a419e0414f94d805329c0e56f0d7620e9eb02e42710be4d2aa2ab
BINTRAY_APIKEY=5a2a220f548e744961c26ca6996680ceccce237f
BINTRAY_USER=guylichtman

if [ $# != 4 ]; then
	echo "Usage: $0 <upload-file> <version> <commit-id> <bintray_pkg>"
	exit 1;
fi
UPLOAD_FILE=$1
VERSION=$2
BINTRAY_PKG=$4

case $BINTRAY_PKG in
	release | dev-snapshot) 
		;;
	*) 
		echo "Invalid BINTRAY_PKG value: [$BINTRAY_PKG]. Valid values are only 'dev-snapshot' or 'release'."
		exit 1
esac
 
echo "@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@ uploading $1 ..... @@@"
echo "@@@@@@@@@@@@@@@@@@@@@@"
curl -k -v -T $UPLOAD_FILE -u$BINTRAY_USER:$BINTRAY_APIKEY -H "X-Bintray-Package:$BINTRAY_PKG" -H "X-Bintray-Version:$VERSION" $BINTRAY_URL/content/$BINTRAY_ACCOUNT/$BINTRAY_REPO/ || exit $?

echo "@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@ Set commit id: $3 ..... @@@"
echo "@@@@@@@@@@@@@@@@@@@@@@"
curl -k -v -u$BINTRAY_USER:$BINTRAY_APIKEY -H "Content-Type: application/json" -X PATCH $BINTRAY_URL/packages/$BINTRAY_ACCOUNT/$BINTRAY_REPO/$BINTRAY_PKG/versions/$VERSION/attributes --data "[{\"name\": \"git-commit\", \"values\" : [\"$3\"], \"type\": \"string\"}]" || exit $?


echo "@@@@@@@@@@@@@@@@@@@@@@@"
echo "@@@ publish content @@@"
echo "@@@@@@@@@@@@@@@@@@@@@@@"
curl -k -v -u$BINTRAY_USER:$BINTRAY_APIKEY -H "Content-Type: application/json" -X POST $BINTRAY_URL/content/$BINTRAY_ACCOUNT/$BINTRAY_REPO/$BINTRAY_PKG/$VERSION/publish --data "{ \"discard\": \"false\" }"
 
 
