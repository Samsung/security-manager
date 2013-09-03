Name:       security-server
Summary:    Security server and utilities
Version:    0.0.73
Release:    1
Group:      Security/Service
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
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
BuildRequires: pkgconfig(libsystemd-daemon)
%{?systemd_requires}

%description
Tizen security server and utilities

%package -n libsecurity-server-client
Summary:    Security server (client)
Group:      Security/Libraries
Requires:   security-server = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libsecurity-server-client
Tizen Security server client libraries

%package -n libsecurity-server-client-devel
Summary:    Security server (client-devel)
Group:      Security/Development
Requires:   libsecurity-server-client = %{version}-%{release}
Requires:   libprivilege-control-devel

%description -n libsecurity-server-client-devel
Development files needed for using the security client

%package -n security-server-devel
Summary:    for web applications (Development)
Group:      Security/Development
Requires:   security-server = %{version}-%{release}

%description -n security-server-devel
Development files for the Tizen security server

%package -n security-server-certs
Summary:    Certificates for web applications.
Group:      Security/Libraries
Requires:   security-server

%description -n security-server-certs
Certificates for the Tizen Web-Runtime

%prep
%setup -q
cp %{SOURCE1001} .

%build
export LDFLAGS+="-Wl,--rpath=%{_libdir}"

%cmake . -DVERSION=%{version} \
        -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}%{!?build_type:RELEASE} \
        -DCMAKE_VERBOSE_MAKEFILE=OFF
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
cp LICENSE %{buildroot}/usr/share/license/libsecurity-server-client
%make_install

mkdir -p %{buildroot}/usr/lib/systemd/system/multi-user.target.wants
mkdir -p %{buildroot}/usr/lib/systemd/system/sockets.target.wants
ln -s ../security-server.service %{buildroot}/usr/lib/systemd/system/multi-user.target.wants/security-server.service
ln -s ../security-server.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server.socket
ln -s ../security-server-data-share.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-data-share.socket
ln -s ../security-server-get-gid.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-get-gid.socket
ln -s ../security-server-privilege-by-pid.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-privilege-by-pid.socket
ln -s ../security-server-exec-path.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-exec-path.socket
ln -s ../security-server-get-object-name.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-get-object-name.socket
ln -s ../security-server-app-permissions.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-app-permissions.socket
ln -s ../security-server-cookie-get.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-cookie-get.socket
ln -s ../security-server-cookie-check.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-cookie-check.socket
ln -s ../security-server-cookie-check-tmp.socket %{buildroot}/usr/lib/systemd/system/sockets.target.wants/security-server-cookie-check-tmp.socket

%clean
rm -rf %{buildroot}

%post
systemctl daemon-reload
if [ "$1" = 1 ]; then
    systemctl restart security-server.service
fi

%preun
if [ "$1" = 0 ]; then
    systemctl stop security-server.service
fi

%postun
systemctl daemon-reload

%post -n libsecurity-server-client -p /sbin/ldconfig

%postun -n libsecurity-server-client -p /sbin/ldconfig

%files -n security-server
%manifest %{_datadir}/security-server.manifest
%attr(755,root,root) /usr/bin/security-server
%{_libdir}/libsecurity-server-commons.so.*
%attr(-,root,root) /usr/lib/systemd/system/multi-user.target.wants/security-server.service
%attr(-,root,root) /usr/lib/systemd/system/security-server.service
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-data-share.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-data-share.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-get-gid.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-get-gid.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-privilege-by-pid.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-privilege-by-pid.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-exec-path.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-exec-path.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-get-object-name.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-get-object-name.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-app-permissions.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-app-permissions.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-cookie-get.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-cookie-get.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-cookie-check.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-cookie-check.socket
%attr(-,root,root) /usr/lib/systemd/system/sockets.target.wants/security-server-cookie-check-tmp.socket
%attr(-,root,root) /usr/lib/systemd/system/security-server-cookie-check-tmp.socket

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
%{_libdir}/libsecurity-server-commons.so
/usr/include/security-server/security-server.h
%{_libdir}/pkgconfig/*.pc
