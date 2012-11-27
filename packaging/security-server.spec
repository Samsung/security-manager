#sbs-git:slp/pkgs/s/security-server security-server 0.0.37
Name:       security-server
Summary:    Security server and utilities
Version:    0.0.47
Release:    1
Group:      TO_BE/FILLED_IN
License:    Apache License, Version 2.0
URL:        N/A
Source0:    %{name}-%{version}.tar.gz
Source1:    security-server.manifest
Source2:    libsecurity-server-client.manifest
BuildRequires: cmake
BuildRequires: zip
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)
BuildRequires: libattr-devel
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(dbus-1)
BuildRequires: pkgconfig(dpl-efl)
BuildRequires: pkgconfig(dpl-utils-efl)
BuildRequires: pkgconfig(dpl-wrt-dao-rw)
BuildRequires: pkgconfig(dpl-dbus-efl)
BuildRequires: pkgconfig(libpcrecpp)
BuildRequires: pkgconfig(icu-i18n)
BuildRequires: pkgconfig(libsoup-2.4)
BuildRequires: pkgconfig(xmlsec1)

%description
Security server and utilities

%package -n libsecurity-server-client
Summary:    Security server (client)
Group:      Development/Libraries
Requires:   security-server = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libsecurity-server-client
Security server package (client)


%package -n libsecurity-server-client-devel
Summary:    Security server (client-devel)
Group:      Development/Libraries
Requires:   libsecurity-server-client = %{version}-%{release}

%description -n libsecurity-server-client-devel
Security server package (client-devel)

%package -n security-server-devel
Summary:    for web applications (Development)
Group:      Development/Libraries
Requires:   security-server = %{version}-%{release}

%description -n security-server-devel
Security daemon for web applications (Development)

%package -n security-server-certs
Summary:    Certificates for web applications.
Group:      Development/Libraries
Requires:   security-server

%description -n security-server-certs
Certificates for wrt.

%prep
%setup -q

%build
export LDFLAGS+="-Wl,--rpath=%{_prefix}/lib"

cmake . -DCMAKE_INSTALL_PREFIX=%{_prefix} \
        -DDPL_LOG="ON"                    \
        -DVERSION=%{version}
make %{?jobs:-j%jobs}


%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
cp LICENSE %{buildroot}/usr/share/license/libsecurity-server-client
%make_install
install -D %{SOURCE1} %{buildroot}%{_datadir}/security-server.manifest
install -D %{SOURCE2} %{buildroot}%{_datadir}/libsecurity-server-client.manifest

%clean
rm -rf %{buildroot}


%post
mkdir -p /etc/rc.d/rc3.d
mkdir -p /etc/rc.d/rc5.d
ln -s /etc/rc.d/init.d/security-serverd /etc/rc.d/rc3.d/S10security-server
ln -s /etc/rc.d/init.d/security-serverd /etc/rc.d/rc5.d/S10security-server
ln -s -f /opt/dbspace/.cert_svc_vcore.db-journal /opt/dbspace/.vcore.db-journal
ln -s -f /opt/dbspace/.cert_svc_vcore.db /opt/dbspace/.vcore.db

if [ -z ${2} ]; then
    echo "This is new install of wrt-security"
    echo "Calling /usr/bin/wrt_security_create_clean_db.sh"
    /usr/bin/wrt_security_create_clean_db.sh
else
    # Find out old and new version of databases
    ACE_OLD_DB_VERSION=`sqlite3 /opt/dbspace/.ace.db ".tables" | grep "DB_VERSION_"`
    ACE_NEW_DB_VERSION=`cat /usr/share/wrt-engine/ace_db.sql | tr '[:blank:]' '\n' | grep DB_VERSION_`
    echo "OLD ace database version ${ACE_OLD_DB_VERSION}"
    echo "NEW ace database version ${ACE_NEW_DB_VERSION}"

    if [ ${ACE_OLD_DB_VERSION} -a ${ACE_NEW_DB_VERSION} ]
    then
        if [ ${ACE_NEW_DB_VERSION} = ${ACE_OLD_DB_VERSION} ]
        then
            echo "Equal database detected so db installation ignored"
        else
            echo "Calling /usr/bin/wrt_security_create_clean_db.sh"
            /usr/bin/wrt_security_create_clean_db.sh
        fi
    else
        echo "Calling /usr/bin/wrt_security_create_clean_db.sh"
        /usr/bin/wrt_security_create_clean_db.sh
    fi
fi

echo "[WRT] wrt-security postinst done ..."

%postun
rm -f /etc/rc.d/rc3.d/S10security-server
rm -f /etc/rc.d/rc5.d/S10security-server

%post -n libsecurity-server-client -p /sbin/ldconfig

%postun -n libsecurity-server-client -p /sbin/ldconfig


%files -n security-server
%manifest %{_datadir}/security-server.manifest
%defattr(-,root,root,-)
/usr/share/security-server/mw-list
%attr(755,root,root) /etc/rc.d/init.d/security-serverd
#/etc/rc.d/rc3.d/S10security-server
#/etc/rc.d/rc5.d/S10security-server
%attr(755,root,root) /usr/bin/security-server
#/usr/bin/sec-svr-util
%{_libdir}/libace*.so
%{_libdir}/libace*.so.*
%{_libdir}/libwrt-ocsp.so
%{_libdir}/libwrt-ocsp.so.*
%{_libdir}/libcommunication-client.so*
/usr/share/wrt-engine/*
%attr(755,root,root) %{_bindir}/wrt-popup
%attr(755,root,root) %{_bindir}/wrt_security_create_clean_db.sh
%attr(755,root,root) %{_bindir}/wrt_security_change_policy.sh
%attr(664,root,root) %{_datadir}/dbus-1/services/*
%attr(664,root,root) /usr/etc/ace/bondixml*
%attr(664,root,root) /usr/etc/ace/UnrestrictedPolicy.xml
%attr(664,root,root) /usr/etc/ace/WAC2.0Policy.xml
%attr(664,root,root) /usr/etc/ace/TizenPolicy.xml
%{_datadir}/license/%{name}

#%files -n security-server-certs
%attr(664,root,root) /opt/share/cert-svc/certs/code-signing/wac/wac.publisherid.pem
%attr(664,root,root) /opt/share/cert-svc/certs/code-signing/wac/tizen.root.preproduction.cert.pem
%attr(664,root,root) /opt/share/cert-svc/certs/code-signing/wac/wac.root.production.pem
%attr(664,root,root) /opt/share/cert-svc/certs/code-signing/wac/wac.root.preproduction.pem
%attr(664,root,root) /opt/share/cert-svc/certs/code-signing/wac/tizen-developer-root-ca.pem
%attr(664,root,root) /opt/share/cert-svc/certs/code-signing/wac/tizen-distributor-root-ca-partner.pem
%attr(664,root,root) /opt/share/cert-svc/certs/code-signing/wac/tizen-distributor-root-ca-public.pem

%files -n libsecurity-server-client
%manifest %{_datadir}/libsecurity-server-client.manifest
%defattr(-,root,root,-)
/usr/lib/libsecurity-server-client.so.*
%{_datadir}/license/libsecurity-server-client

%files -n libsecurity-server-client-devel
%defattr(-,root,root,-)
/usr/lib/libsecurity-server-client.so
/usr/include/security-server/security-server.h
/usr/lib/pkgconfig/security-server.pc
%{_includedir}/wrt-security/*
%{_includedir}/ace/*
%{_includedir}/ace-dao-ro/*
%{_includedir}/ace-dao-rw/*
%{_includedir}/ace-client/*
%{_includedir}/ace-settings/*
%{_includedir}/ace-install/*
%{_includedir}/ace-common/*
%{_includedir}/ace-popup-validation/*
%{_includedir}/wrt-ocsp/*
%{_libdir}/pkgconfig/*.pc

