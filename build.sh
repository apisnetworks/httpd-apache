#!/bin/sh
rpmbuild --define 'dist .apnscp' --define "_topdir `pwd`" -bb SPECS/httpd.spec
