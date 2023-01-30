%define contentdir %{_datadir}/httpd
%define docroot /var/www
%define suexec_caller apache
%define mmn 20120211
%define epoch 2
%if 0%{?rhel} < 8
%define oldmmnisa %{mmn}-%{__isa_name}-%{__isa_bits}
%else
%define oldmmnisa %{mmn}-%{__isa_name}
%endif
%define mmnisa %{mmn}%{__isa_name}%{__isa_bits}
%define vstring apnscp

# Drop automatic provides for module DSOs
%{?filter_setup:
%filter_provides_in %{_libdir}/httpd/modules/.*\.so$
%filter_setup
}

Summary: Apache HTTP Server
Name: httpd
Version: 2.4.55
Release: 1%{?dist}
Epoch: %{epoch}
URL: http://httpd.apache.org/
Vendor: Apache Software Foundation
Source0: http://www.apache.org/dist/httpd/httpd-%{version}.tar.bz2
Source1: httpd.conf
Source2: httpd.logrotate
Source3: httpd.service
Source4: httpd.init
Source5: httpd.sysconf
Source6: htcacheclean.service
Source7: htcacheclean.sysconf
Source8: httpd-apnscp-rewrite-map.conf
Source9: httpd.tmpfiles
Source10: httpd-custom.conf

Patch0: suexec-apnscp.patch
Patch1: httpd-apxs.patch
Patch2: apxs-apnscp.patch
Patch3: httpd-2.4-force-symlinks-owner.patch
Patch4: httpd-docroot-vpath.patch
Patch5: httpd-2.4-suexec-pam.patch

License: Apache License, Version 2.0
Group: System Environment/Daemons
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires: autoconf, perl, pkgconfig, findutils
BuildRequires: zlib-devel, libselinux-devel, libuuid-devel
BuildRequires: brotli-devel >= 1.0.5
BuildRequires: apr-devel >= 1.4.0, apr-util-devel >= 1.4.0, pcre-devel >= 5.0, libnghttp2
BuildRequires: systemd-devel
Requires: /etc/mime.types
Requires: /usr/bin/x86_64-redhat-linux-gcc
Requires: util-linux
Requires: brotli >= 1.0.5
Obsoletes: httpd-suexec
Conflicts: httpd < 2.4.30
Requires(pre): /usr/sbin/useradd
Provides: webserver
Provides: mod_dav = %{version}-%{release}, httpd-suexec = %{version}-%{release}
Provides: httpd-mmn = %{mmn}, httpd-mmn = %{mmnisa}, httpd-mmn = %{oldmmnisa}
Provides: httpd-filesystem
Requires(preun): systemd-units
Requires(postun): systemd-units
Requires(post): systemd-units
Requires: httpd-tools = %{epoch}:%{version}-%{release}

%description
Apache is a powerful, full-featured, efficient, and freely-available
Web server. Apache is also the most popular Web server on the
Internet.

%package devel
Group: Development/Libraries
Summary: Development tools for the Apache HTTP server.
Epoch: %{epoch}
Obsoletes: secureweb-devel, apache-devel
Requires: apr-devel, apr-util-devel, pkgconfig, libtool
Requires: httpd = %{epoch}:%{version}-%{release}

%description devel
The httpd-devel package contains the APXS binary and other files
that you need to build Dynamic Shared Objects (DSOs) for the
Apache HTTP Server.

If you are installing the Apache HTTP server and you want to be
able to compile or develop additional modules for Apache, you need
to install this package.

%package manual
Group: Documentation
Summary: Documentation for the Apache HTTP server.
Epoch: %{epoch}
Requires: httpd = %{epoch}:%{version}-%{release}
Obsoletes: secureweb-manual, apache-manual

%description manual
The httpd-manual package contains the complete manual and
reference guide for the Apache HTTP server. The information can
also be found at http://httpd.apache.org/docs/.

%package tools
Group: System Environment/Daemons
Summary: Tools for use with the Apache HTTP Server
Epoch: %{epoch}

%description tools
The httpd-tools package contains tools which can be used with
the Apache HTTP Server.

%package -n mod_authnz_ldap
Group: System Environment/Daemons
Summary: LDAP modules for the Apache HTTP server
Epoch: %{epoch}
BuildRequires: openldap-devel
Requires: httpd = %{epoch}:%{version}-%{release}, httpd-mmn = %{mmn}, apr-util-ldap

%description -n mod_authnz_ldap
The mod_authnz_ldap module for the Apache HTTP server provides
authentication and authorization against an LDAP server, while
mod_ldap provides an LDAP cache.

%package -n mod_proxy_html
Group: System Environment/Daemons
Summary: Proxy HTML filter modules for the Apache HTTP server
Epoch: %{epoch}
BuildRequires: libxml2-devel
Requires: httpd = %{epoch}:%{version}-%{release}, httpd-mmn = %{mmn}

%description -n mod_proxy_html
The mod_proxy_html module for the Apache HTTP server provides
a filter to rewrite HTML links within web content when used within
a reverse proxy environment. The mod_xml2enc module provides
enhanced charset/internationalisation support for mod_proxy_html.

%package -n mod_ssl
Group: System Environment/Daemons
Summary: SSL/TLS module for the Apache HTTP server
Epoch: %{epoch}
BuildRequires: openssl-devel
Requires(post): openssl, /bin/cat
Requires(pre): httpd
Requires: httpd = %{epoch}:%{version}-%{release}, httpd-mmn = %{mmn}

%description -n mod_ssl
The mod_ssl module provides strong cryptography for the Apache Web
server via the Secure Sockets Layer (SSL) and Transport Layer
Security (TLS) protocols.

%prep
%setup -q
%patch0 -p1
%patch1 -p1
%patch2 -p1
%patch3 -p1 
%patch4 -p1
%patch5 -p1

sed -i '/^#define PLATFORM/s/Unix/%{vstring}/' os/unix/os.h
sed -i 's/@RELEASE@/%{release}/' server/core.c

# Prevent use of setcap in "install-suexec-caps" target.
sed -i '/suexec/s,setcap ,echo Skipping setcap for ,' Makefile.in

# Safety check: prevent build if defined MMN does not equal upstream MMN.
vmmn=`echo MODULE_MAGIC_NUMBER_MAJOR | cpp -include include/ap_mmn.h | sed -n '
/^2/p'`
if test "x${vmmn}" != "x%{mmn}"; then
   : Error: Upstream MMN is now ${vmmn}, packaged MMN is %{mmn}.
   : Update the mmn macro and rebuild.
   exit 1
fi

# Before configure; fix location of build dir in generated apxs
%{__perl} -pi -e "s:\@exp_installbuilddir\@:%{_libdir}/httpd/build:g" \
  support/apxs.in

%build
# forcibly prevent use of bundled apr, apr-util, pcre
rm -rf srclib/{apr,apr-util,pcre}

# regenerate configure scripts
autoheader && autoconf || exit 1

export LDFLAGS="-Wl,-z,relro,-z,now"

%configure \
	--enable-layout=RPM \
	--libdir=%{_libdir} \
	--sysconfdir=%{_sysconfdir}/httpd/conf \
	--includedir=%{_includedir}/httpd \
	--libexecdir=%{_libdir}/httpd/modules \
	--datadir=%{contentdir} \
        --with-installbuilddir=%{_libdir}/httpd/build \
        --enable-mpms-shared=all \
        --with-apr=%{_prefix} --with-apr-util=%{_prefix} \
	--enable-suexec --with-suexec \
	--with-suexec-caller=%{suexec_caller} \
	--with-suexec-docroot=%{contentdir} \
	--with-suexec-logfile=%{_localstatedir}/log/httpd/suexec.log \
	--with-suexec-bin=%{_sbindir}/suexec \
	--with-suexec-uidmin=1000 --with-suexec-gidmin=1000 \
        --enable-pie \
        --with-pcre \
        --enable-mods-shared=all --disable-distcache --disable-lua \
        --enable-ssl --with-ssl --enable-bucketeer --enable-systemd \
        --enable-case-filter --enable-case-filter-in --enable-brotli \
        --disable-imagemap --enable-nonportable-atomics=yes $*
# Non-portables should be fine as all apnscp distributions run on x86-64

make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT install

# Install systemd service files
mkdir -p $RPM_BUILD_ROOT%{_unitdir} $RPM_BUILD_ROOT%{_sysconfdir}/systemd/user
for s in httpd htcacheclean; do
  install -p -m 644 $RPM_SOURCE_DIR/${s}.service \
                    $RPM_BUILD_ROOT%{_unitdir}/${s}.service
done

install -p -m 644 $RPM_SOURCE_DIR/httpd-apnscp-rewrite-map.conf $RPM_BUILD_ROOT/%{_sysconfdir}/httpd/conf
install -p -m 644 $RPM_SOURCE_DIR/httpd.conf $RPM_BUILD_ROOT/%{_sysconfdir}/httpd/conf
install -p -m 644 $RPM_SOURCE_DIR/httpd-custom.conf $RPM_BUILD_ROOT/%{_sysconfdir}/httpd/conf
install -p -m 755 $RPM_SOURCE_DIR/httpd.init $RPM_BUILD_ROOT/%{_sysconfdir}/systemd/user/

%if 0%{?rhel} < 8
sed -i -e '/\sTLSv1\.3/d' $RPM_BUILD_ROOT/%{_sysconfdir}/httpd/conf/httpd.conf
%endif

# for holding mod_dav lock database
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/lib/dav

# create a prototype session cache
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/cache/mod_ssl
touch $RPM_BUILD_ROOT%{_localstatedir}/cache/mod_ssl/scache.{dir,pag,sem}

mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf/{domains,virtual,personalities}
echo 80 > $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf/personalities/httpd

# Make the MMN accessible to module packages
echo %{mmn} > $RPM_BUILD_ROOT%{_includedir}/httpd/.mmn

# HTTP/1.0 whitelist
touch $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf/http10

# tmpfiles.d configuration
mkdir -p $RPM_BUILD_ROOT%{_prefix}/lib/tmpfiles.d
install -m 644 -p $RPM_SOURCE_DIR/httpd.tmpfiles \
   $RPM_BUILD_ROOT%{_prefix}/lib/tmpfiles.d/httpd.conf

# Set up /var directories
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/log/httpd
mkdir -p $RPM_BUILD_ROOT%{_localstatedir}/cache/httpd/cache-root

# symlinks for /etc/httpd
ln -s ../..%{_localstatedir}/log/httpd $RPM_BUILD_ROOT/etc/httpd/logs
ln -s ../..%{_localstatedir}/run $RPM_BUILD_ROOT/etc/httpd/run
ln -s ../..%{_libdir}/httpd/modules $RPM_BUILD_ROOT/etc/httpd/modules
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/httpd/conf.d

# install log rotation stuff
mkdir -p $RPM_BUILD_ROOT/etc/logrotate.d
install -m644 $RPM_SOURCE_DIR/httpd.logrotate \
	$RPM_BUILD_ROOT/etc/logrotate.d/httpd

# Remove unpackaged files
rm -rf $RPM_BUILD_ROOT%{_libdir}/httpd/modules/*.exp \
       $RPM_BUILD_ROOT%{contentdir}/cgi-bin/*

# Make suexec a+rw so it can be stripped.  %%files lists real permissions
chmod 755 $RPM_BUILD_ROOT%{_sbindir}/suexec

rm -rf $RPM_BUILD_ROOT/etc/httpd/conf/{original,extra}

mkdir $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig
for s in httpd htcacheclean; do
  install -m 644 -p $RPM_SOURCE_DIR/${s}.sysconf \
                    $RPM_BUILD_ROOT%{_sysconfdir}/sysconfig/${s}
done

# remove manual sources
find $RPM_BUILD_ROOT%{contentdir}/manual \( \
    -name \*.xml -o -name \*.xml.* -o -name \*.ent -o -name \*.xsl -o -name \*.dtd \
    \) -print0 | xargs -0 rm -f

# Remove unpackaged files
rm -rf \
      $RPM_BUILD_ROOT%{_sysconfdir}/rc.d

%pre
# Add the "apache" group and user
/usr/sbin/groupadd -g 48 -r apache 2> /dev/null || :
/usr/sbin/useradd -c "Apache" -u 48 -g 48 \
  -s /sbin/nologin -r -d %{contentdir} apache 2> /dev/null || :

%post
# Copy old LoadModule config injected below MODULE_MARKER
if [[ -f %{_sysconfdir}/httpd/conf/httpd.conf.rpmsave ]] ; then
  awk 'BEGIN {IGNORECASE = 1} /^\s*LoadModule\s*/ && MATCH{print;} /^#\s*MODULE_MARKER/{MATCH=1}' \
    %{_sysconfdir}/httpd/conf/httpd.conf.rpmsave | sed -n -i -e \
    '/^\s*#\s*MODULE_MARKER\s*/r /dev/stdin' -e p \
    %{_sysconfdir}/httpd/conf/httpd.conf

  # Validate php_module is present
  grep -E -q 'LoadModule\s+php[[:digit:]]_module' %{_sysconfdir}/httpd/conf/httpd.conf
  if test $? -ne 0; then
    LINE="$(grep -m1 -E 'LoadModule\s+php[[:digit:]]_module' %{_sysconfdir}/httpd/conf/httpd.conf.rpmsave)"
    if [[ "$LINE" != "" ]] ; then
      awk '/^#\s*MODULE_MARKER/{print; print "'"$LINE"'";next}1' \
        %{_sysconfdir}/httpd/conf/httpd.conf > %{_sysconfdir}/httpd/conf/httpd.$$ && \
        mv %{_sysconfdir}/httpd/conf/httpd.$$ %{_sysconfdir}/httpd/conf/httpd.conf
    fi
  fi
fi

%systemd_post httpd.service htcacheclean.service
httxt2dbm -f SDBM -i %{_sysconfdir}/httpd/conf/http10 -o %{_sysconfdir}/httpd/conf/http10

! compgen -G "%{_sysconfdir}/httpd/conf/domains/*" && for path in /home/virtual/site* ; do
  SITE=${SITE##*/}
  [[ -f $path/info/domain_map ]] || continue
  httxt2dbm -f SDBM -i $path/info/domain_map -o %{_sysconfdir}/httpd/conf/domains/${SITE}
done

[[ -f %{_sysconfdir}/httpd/conf/virtual-httpd-built ]] || \
  env OPTIONS="-DNO_SSL" %{_sysconfdir}/systemd/user/httpd.init buildconfig

%preun
%systemd_preun httpd.service htcacheclean.service

%postun
%systemd_postun httpd.service

%posttrans
test -f /etc/sysconfig/httpd-disable-posttrans || \
  /bin/systemctl try-restart httpd.service htcacheclean.service >/dev/null 2>&1 || :

%define sslcert %{_sysconfdir}/pki/tls/certs/server.pem

%post -n mod_ssl
umask 077

ln -fs %{sslcert} %{_sysconfdir}/httpd/conf/server.pem
if [ -f %{sslcert} ] ; then
  exit 0
fi

cat << EOF | %{_bindir}/openssl req -rand /proc/cpuinfo:/proc/dma:/proc/filesystems:/proc/interrupts:/proc/ioports:/proc/uptime -nodes \
  -newkey rsa:2048 -keyout %{sslcert} -x509 -days 365 -out %{sslcert} 2>/dev/null
FQDN="${FQDN:=$(hostname)}"
--
SomeState
SomeCity
SomeOrganization
SomeOrganizationalUnit
${FQDN}
root@${FQDN}
EOF

%check
# Check the built modules are all PIC
if readelf -d $RPM_BUILD_ROOT%{_libdir}/httpd/modules/*.so | grep TEXTREL; then
   : modules contain non-relocatable code
   exit 1
fi

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)

%doc ABOUT_APACHE README CHANGES LICENSE NOTICE

%dir %{_sysconfdir}/httpd
%{_sysconfdir}/httpd/modules
%{_sysconfdir}/httpd/logs
%{_sysconfdir}/httpd/run
%dir %{_sysconfdir}/httpd/conf
%dir %{_sysconfdir}/httpd/conf.d
%dir %{_sysconfdir}/httpd/conf/domains
%dir %{_sysconfdir}/httpd/conf/personalities
%dir %{_sysconfdir}/httpd/conf/virtual
%config(noreplace) %{_sysconfdir}/httpd/conf/personalities/httpd
%config %{_sysconfdir}/httpd/conf/httpd.conf
%config(noreplace) %{_sysconfdir}/httpd/conf/httpd-custom.conf
%config %{_sysconfdir}/httpd/conf/httpd-apnscp-rewrite-map.conf
%config(noreplace) %{_sysconfdir}/httpd/conf/magic
%config(noreplace) %{_sysconfdir}/httpd/conf/mime.types
%config(noreplace) %{_sysconfdir}/httpd/conf/http10

%config(noreplace) %{_sysconfdir}/sysconfig/h*
%{_prefix}/lib/tmpfiles.d/httpd.conf

%config %{_sysconfdir}/logrotate.d/httpd
%{_sysconfdir}/systemd/user/httpd.init
%{_unitdir}/*.service

%{_sbindir}/fcgistarter
%{_sbindir}/htcacheclean
%{_sbindir}/httpd
%{_sbindir}/apachectl
%attr(4510,root,%{suexec_caller}) %{_sbindir}/suexec

%dir %{_libdir}/httpd
%dir %{_libdir}/httpd/modules
%{_libdir}/httpd/modules/mod_access_compat.so
%{_libdir}/httpd/modules/mod_actions.so
%{_libdir}/httpd/modules/mod_alias.so
%{_libdir}/httpd/modules/mod_allowmethods.so
%{_libdir}/httpd/modules/mod_asis.so
%{_libdir}/httpd/modules/mod_auth_basic.so
%{_libdir}/httpd/modules/mod_auth_digest.so
%{_libdir}/httpd/modules/mod_auth_form.so
%{_libdir}/httpd/modules/mod_authn_anon.so
%{_libdir}/httpd/modules/mod_authn_core.so
%{_libdir}/httpd/modules/mod_authn_dbd.so
%{_libdir}/httpd/modules/mod_authn_dbm.so
%{_libdir}/httpd/modules/mod_authn_file.so
%{_libdir}/httpd/modules/mod_authn_socache.so
%{_libdir}/httpd/modules/mod_authz_core.so
%{_libdir}/httpd/modules/mod_authz_dbd.so
%{_libdir}/httpd/modules/mod_authz_dbm.so
%{_libdir}/httpd/modules/mod_authz_groupfile.so
%{_libdir}/httpd/modules/mod_authz_host.so
%{_libdir}/httpd/modules/mod_authz_owner.so
%{_libdir}/httpd/modules/mod_authz_user.so
%{_libdir}/httpd/modules/mod_autoindex.so
%{_libdir}/httpd/modules/mod_brotli.so
%{_libdir}/httpd/modules/mod_bucketeer.so
%{_libdir}/httpd/modules/mod_buffer.so
%{_libdir}/httpd/modules/mod_cache_disk.so
%{_libdir}/httpd/modules/mod_cache_socache.so
%{_libdir}/httpd/modules/mod_cache.so
%{_libdir}/httpd/modules/mod_case_filter.so
%{_libdir}/httpd/modules/mod_case_filter_in.so
%{_libdir}/httpd/modules/mod_cgid.so
%{_libdir}/httpd/modules/mod_charset_lite.so
%{_libdir}/httpd/modules/mod_data.so
%{_libdir}/httpd/modules/mod_dav_fs.so
%{_libdir}/httpd/modules/mod_dav_lock.so
%{_libdir}/httpd/modules/mod_dav.so
%{_libdir}/httpd/modules/mod_dbd.so
%{_libdir}/httpd/modules/mod_deflate.so
%{_libdir}/httpd/modules/mod_dialup.so
%{_libdir}/httpd/modules/mod_dir.so
%{_libdir}/httpd/modules/mod_dumpio.so
%{_libdir}/httpd/modules/mod_echo.so
%{_libdir}/httpd/modules/mod_env.so
%{_libdir}/httpd/modules/mod_expires.so
%{_libdir}/httpd/modules/mod_ext_filter.so
%{_libdir}/httpd/modules/mod_file_cache.so
%{_libdir}/httpd/modules/mod_filter.so
%{_libdir}/httpd/modules/mod_headers.so
%{_libdir}/httpd/modules/mod_heartbeat.so
%{_libdir}/httpd/modules/mod_heartmonitor.so
%{_libdir}/httpd/modules/mod_http2.so
%{_libdir}/httpd/modules/mod_include.so
%{_libdir}/httpd/modules/mod_info.so
%{_libdir}/httpd/modules/mod_lbmethod_bybusyness.so
%{_libdir}/httpd/modules/mod_lbmethod_byrequests.so
%{_libdir}/httpd/modules/mod_lbmethod_bytraffic.so
%{_libdir}/httpd/modules/mod_lbmethod_heartbeat.so
%{_libdir}/httpd/modules/mod_log_config.so
%{_libdir}/httpd/modules/mod_log_debug.so
%{_libdir}/httpd/modules/mod_log_forensic.so
%{_libdir}/httpd/modules/mod_logio.so
%{_libdir}/httpd/modules/mod_macro.so
%{_libdir}/httpd/modules/mod_mime_magic.so
%{_libdir}/httpd/modules/mod_mime.so
%{_libdir}/httpd/modules/mod_mpm_event.so
%{_libdir}/httpd/modules/mod_mpm_prefork.so
%{_libdir}/httpd/modules/mod_mpm_worker.so
%{_libdir}/httpd/modules/mod_negotiation.so
%{_libdir}/httpd/modules/mod_proxy_ajp.so
%{_libdir}/httpd/modules/mod_proxy_balancer.so
%{_libdir}/httpd/modules/mod_proxy_connect.so
%{_libdir}/httpd/modules/mod_proxy_express.so
%{_libdir}/httpd/modules/mod_proxy_fcgi.so
%{_libdir}/httpd/modules/mod_proxy_fdpass.so
%{_libdir}/httpd/modules/mod_proxy_ftp.so
%{_libdir}/httpd/modules/mod_proxy_http.so
%{_libdir}/httpd/modules/mod_proxy_scgi.so
%{_libdir}/httpd/modules/mod_proxy_wstunnel.so
%{_libdir}/httpd/modules/mod_proxy_uwsgi.so
%{_libdir}/httpd/modules/mod_proxy_hcheck.so
%{_libdir}/httpd/modules/mod_proxy.so
%{_libdir}/httpd/modules/mod_ratelimit.so
%{_libdir}/httpd/modules/mod_reflector.so
%{_libdir}/httpd/modules/mod_remoteip.so
%{_libdir}/httpd/modules/mod_reqtimeout.so
%{_libdir}/httpd/modules/mod_request.so
%{_libdir}/httpd/modules/mod_rewrite.so
%{_libdir}/httpd/modules/mod_sed.so
%{_libdir}/httpd/modules/mod_session_cookie.so
%{_libdir}/httpd/modules/mod_session_crypto.so
%{_libdir}/httpd/modules/mod_session_dbd.so
%{_libdir}/httpd/modules/mod_session.so
%{_libdir}/httpd/modules/mod_setenvif.so
%{_libdir}/httpd/modules/mod_slotmem_plain.so
%{_libdir}/httpd/modules/mod_slotmem_shm.so
%{_libdir}/httpd/modules/mod_socache_dbm.so
%{_libdir}/httpd/modules/mod_socache_memcache.so
%{_libdir}/httpd/modules/mod_socache_redis.so
%{_libdir}/httpd/modules/mod_socache_shmcb.so
%{_libdir}/httpd/modules/mod_speling.so
%{_libdir}/httpd/modules/mod_status.so
%{_libdir}/httpd/modules/mod_substitute.so
%{_libdir}/httpd/modules/mod_suexec.so
%{_libdir}/httpd/modules/mod_systemd.so
%{_libdir}/httpd/modules/mod_unique_id.so
%{_libdir}/httpd/modules/mod_unixd.so
%{_libdir}/httpd/modules/mod_userdir.so
%{_libdir}/httpd/modules/mod_usertrack.so
%{_libdir}/httpd/modules/mod_version.so
%{_libdir}/httpd/modules/mod_vhost_alias.so
%{_libdir}/httpd/modules/mod_watchdog.so

%dir %{contentdir}
%dir %{contentdir}/cgi-bin
%dir %{contentdir}/html
%dir %{contentdir}/icons
%dir %{contentdir}/error
%dir %{contentdir}/error/include
%{contentdir}/icons/*
%{contentdir}/error/README
%{contentdir}/html/index.html
%config(noreplace) %{contentdir}/error/*.var
%config(noreplace) %{contentdir}/error/include/*.html

%attr(0700,root,root) %dir %{_localstatedir}/log/httpd

%attr(0700,apache,apache) %dir %{_localstatedir}/lib/dav
%attr(0700,apache,apache) %dir %{_localstatedir}/cache/httpd/cache-root

%{_mandir}/man1/*
%{_mandir}/man8/suexec*
%{_mandir}/man8/apachectl.8*
%{_mandir}/man8/httpd.8*
%{_mandir}/man8/htcacheclean.8*
%{_mandir}/man8/fcgistarter.8*

%files manual
%defattr(-,root,root)
%{contentdir}/manual
%{contentdir}/error/README

%files tools
%defattr(-,root,root)
%{_bindir}/ab
%{_bindir}/htdbm
%{_bindir}/htdigest
%{_bindir}/htpasswd
%{_bindir}/logresolve
%{_bindir}/httxt2dbm
%{_sbindir}/rotatelogs
%{_mandir}/man1/htdbm.1*
%{_mandir}/man1/htdigest.1*
%{_mandir}/man1/htpasswd.1*
%{_mandir}/man1/httxt2dbm.1*
%{_mandir}/man1/ab.1*
%{_mandir}/man1/logresolve.1*
%{_mandir}/man8/rotatelogs.8*
%doc LICENSE NOTICE

%files -n mod_authnz_ldap
%defattr(-,root,root)
%{_libdir}/httpd/modules/mod_ldap.so
%{_libdir}/httpd/modules/mod_authnz_ldap.so

%files -n mod_proxy_html
%defattr(-,root,root)
%{_libdir}/httpd/modules/mod_proxy_html.so
%{_libdir}/httpd/modules/mod_xml2enc.so

%files -n mod_ssl
%defattr(-,root,root)
%{_libdir}/httpd/modules/mod_ssl.so
%attr(0700,apache,root) %dir %{_localstatedir}/cache/mod_ssl
%attr(0600,apache,root) %ghost %{_localstatedir}/cache/mod_ssl/scache.dir
%attr(0600,apache,root) %ghost %{_localstatedir}/cache/mod_ssl/scache.pag
%attr(0600,apache,root) %ghost %{_localstatedir}/cache/mod_ssl/scache.sem

%files devel
%defattr(-,root,root)
%{_includedir}/httpd
%{_bindir}/apxs
%{_sbindir}/checkgid
%{_bindir}/dbmmanage
%{_sbindir}/envvars*
%{_mandir}/man1/dbmmanage.1*
%{_mandir}/man1/apxs.1*
%dir %{_libdir}/httpd/build
%{_libdir}/httpd/build/*.mk
%{_libdir}/httpd/build/instdso.sh
%{_libdir}/httpd/build/config.nice
%{_libdir}/httpd/build/mkdir.sh

%changelog
* Wed Jun 01 2022 Matt Saladna <matt@apisnetworks.com> - 2.4.53-2.apnscp
- TLS_CHACHA20_POLY1305_SHA256 cipher support 
- Reintroduce FollowSymLinks as PrivilegedSymlinks
- Use /dev/random for startup entropy, urandom for connections

* Thu Apr 29 2021 Matt Saladna <matt@apisnetworks.com> - 2.4.46-5.apnscp
- Invalid parsing on two-letter domains
- CGI cgroup binding

* Tue Dec 29 2020 Matt Saladna <matt@apisnetworks.com> - 2.4.46-4.apnscp
- Provide httpd-filesystem dependency

* Mon Dec 07 2020 Matt Saladna <matt@apisnetworks.com> - 2.4.46-3.apnscp
- TLSv1.3
- PHP8 ISAPI compatibility

* Sun Oct 04 2020 Matt Saladna <matt@apisnetworks.com> - 2.4.46-2.apnscp
- .raw profiles

* Fri Aug 07 2020 Matt Saladna <matt@apisnetworks.com> - 2.4.46-1.apnscp
- Errata update

* Sun Jul 05 2020 Matt Saladna <matt@apisnetworks.com> - 2.4.43-4.apnscp
- TLSv1.3 enablement 

* Mon Jun 08 2020 Matt Saladna <matt@apisnetworks.com> - 2.4.43-2.apnscp
- Flexible SSL compatibility
- !PHP_INSTALLED case covered per-virtualhost
- Improve SSL detection routine

* Wed Apr 01 2020 Matt Saladna <matt@apisnetworks.com> - 2.4.43-1.apnscp
- Version bump
- Account reprioritization

* Tue Mar 31 2020 Matt Saladna <matt@apisnetworks.com> - 2.4.41-9.apnscp
- mod_rewrite implicit path translation
- Remove TLSv1.0/1.1
- Directive conversion, FollowSymLinks => SymLinksIfOwnerMatch
- Bump suexec user requirements to RHEL7

* Sun Feb 16 2020 Matt Saladna <matt@apisnetworks.com> - 2.4.41-8.apnscp
- FollowSymLinks treated as SymLinksIfOwnerMatch

* Fri Dec 06 2019 Matt Saladna <matt@apisnetworks.com> - 2.4.41-7.apnscp
- mod_systemd backport

* Wed Nov 27 2019 Matt Saladna <matt@apisnetworks.com> - 2.4.41-6.apnscp
- Export runtime settings to configtest

* Mon Nov 25 2019 Matt Saladna <matt@apisnetworks.com> - 2.4.41-5.apnscp
- Handle killing rogue processes with general port binds
- Migrate ulimits to systemd

* Sat Nov 23 2019 Matt Saladna <matt@apisnetworks.com> - 2.4.41-3.apnscp
- Populate htcacheclean PID directory prestart 

* Sat Sep 07 2019 Matt Saladna <matt@apisnetworks.com> - 2.4.41-2.apnscp
- Increase proxy timeout to 60 seconds

* Thu Aug 01 2019 Matt Saladna <matt@apisnetworks.com> - 2.4.39-5.apnscp
- Hotfix insensitive regex check on "libphp"
- apxs LoadModule placement dependent on MODULE_MARKER

* Wed Jul 31 2019 Matt Saladna <matt@apisnetworks.com> - 2.4.39-4.apnscp
- Set ServerName
- Filter conf.d/ inclusion

* Wed May 08 2019 Matt Saladna <matt@apisnetworks.com> - 2.4.39-3.apnscp
- Enable Brotli

* Fri Apr 19 2019 Matt Saladna <matt@apisnetworks.com> - 2.4.39-2.apnscp
- Populate VPATH for all conditions

* Tue Apr 02 2019 Matt Saladna <matt@apisnetworks.com> - 2.4.39-1.apnscp
- Version bump
- CVE-2019-0211: privilege escalation from modules' scripts

* Mon Feb 25 2019 Matt Saladna <matt@apisnetworks.com> - 2.4.38-5.apnscp
- Disable posix_getpwnam, +INCLUDES
- DAV optional

* Tue Jan 22 2019 Matt Saladna <matt@apisnetworks.com> - 2.4.38-1.apnscp
- Version bump

* Wed Oct 24 2018 Matt Saladna <matt@apisnetworks.com> - 2.4.37-1.apnscp
- Version bump

* Wed Oct 03 2018 Matt Saladna <matt@apisnetworks.com> - 2.4.35-20181003.apnscp
- Acquire lock on init

* Tue Sep 25 2018 Matt Saladna <matt@apisnetworks.com> - 2.4.35-1.apnscp
- Version upgrade

* Thu Sep 13 2018 Matt Saladna <matt@apisnetworks.com> - 2.4.34-20180913.apnscp
- Compress application/json
- Add brotli support
- CACHE_BOTH enables both cache backends
- Passenger/cgroup overlap directive
- Validate phpX_module presence

* Mon Jul 16 2018 Matt Saladna <matt@apisnetworks.com> - 2.4.34-1.apnscp
- svg deflate support
- Update Apache
- Cache optionally enrolled
- suexec: remove docroot check

* Thu Jun 28 2018 Matt Saladna <matt@apisnetworks.com> - 2.4.33-2.apnscp
- Inherit dummyset rules before htaccess parsing (Horde)
- Correct symlink rules, bandwidth log alias
- Migrate modules on upgrade
- Skip addon domain lookups on primary domain match
- Restrict .htaccess lookups below fst/

* Mon Apr 23 2018 Matt Saladna <matt@apisnetworks.com> - 2.4.33-1.apnscp
- Initial release
