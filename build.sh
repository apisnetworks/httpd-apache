#!/bin/sh
rpmbuild --define "dist ${DIST:-''}.apnscp" --define "_topdir `pwd`" -ba SPECS/httpd.spec
