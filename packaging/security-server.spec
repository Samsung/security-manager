#sbs-git:slp/pkgs/s/security-server security-server 0.0.37
Name:       security-server
Summary:    Security server and utilities
Version:    0.0.73
Release:    1
Group:      TO_BE/FILLED_IN
License:    Apache License, Version 2.0
URL:        N/A
Source0:    %{name}-%{version}.tar.gz
Source1:    security-server.manifest
Source2:    libsecurity-server-client.manifest
Source3:    security-server.service
BuildRequires: cmake
BuildRequires: zip
BuildRequires: pkgconfig(dlog)
BuildRequires: pkgconfig(openssl)
BuildRequires: libattr-devel
BuildRequires: pkgconfig(libsmack)
Requires(preun):  systemd
Requires(post):   systemd
Requires(postun): systemd
BuildRequires: pkgconfig(libprivilege-control)

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

#%package -n wrt-security
#Summary:    wrt-security-daemon and client libraries.
#Group:      Development/Libraries
#Requires(post): /sbin/ldconfig
#Requires(postun): /sbin/ldconfig
#
#%description -n wrt-security
#Wrt-security-daemon and client libraries.
#
#%package -n wrt-security-devel
#Summary:    Header files for client libraries.
#Group:      Development/Libraries
#Requires:   wrt-security = %{version}-%{release}
#
#%description -n wrt-security-devel
#Developer files for client libraries.

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
export LDFLAGS+="-Wl,--rpath=%{_libdir}"

%cmake . -DVERSION=%{version} \
        -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}
make %{?jobs:-j%jobs}


%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
cp LICENSE %{buildroot}/usr/share/license/libsecurity-server-client
%make_install
install -D %{SOURCE1} %{buildroot}%{_datadir}/security-server.manifest
install -D %{SOURCE2} %{buildroot}%{_datadir}/libsecurity-server-client.manifest

mkdir -p %{buildroot}/usr/lib/systemd/system/multi-user.target.wants
install -m 0644 %{SOURCE3} %{buildroot}/usr/lib/systemd/system/security-server.service
ln -s ../security-server.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/security-server.service


%preun
if [ $1 == 0 ]; then
    systemctl stop security-server.service
fi

%post
systemctl daemon-reload
if [ $1 == 1 ]; then
    systemctl restart security-server.service
fi
mkdir -p /etc/rc.d/rc3.d
mkdir -p /etc/rc.d/rc5.d
ln -sf /etc/rc.d/init.d/security-serverd /etc/rc.d/rc3.d/S10security-server
ln -sf /etc/rc.d/init.d/security-serverd /etc/rc.d/rc5.d/S10security-server

%postun
systemctl daemon-reload
if [ "$1" = 0 ]; then
    rm -f /etc/rc.d/rc3.d/S10security-server
    rm -f /etc/rc.d/rc5.d/S10security-server
fi

%post -n libsecurity-server-client -p /sbin/ldconfig

%postun -n libsecurity-server-client -p /sbin/ldconfig

%files -n security-server
%manifest %{name}.manifest
%defattr(-,root,root,-)
/usr/lib/systemd/system/multi-user.target.wants/security-server.service
/usr/lib/systemd/system/security-server.service
%attr(755,root,root) /etc/rc.d/init.d/security-serverd
%attr(755,root,root) /usr/bin/security-server

%{_datadir}/license/%{name}

%files -n libsecurity-server-client
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_libdir}/libsecurity-server-client.so.*
%{_datadir}/license/libsecurity-server-client

%files -n libsecurity-server-client-devel
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_libdir}/libsecurity-server-client.so
/usr/include/security-server/security-server.h
%{_libdir}/pkgconfig/*.pc
