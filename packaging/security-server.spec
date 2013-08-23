Name:       security-server
Summary:    Security server and utilities
Version:    0.0.73
Release:    1
Group:      Security/Service
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source2:    libsecurity-server-client.manifest
Source3:    security-server.service
Source1001: %{name}.manifest
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
        -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}
make %{?jobs:-j%jobs}


%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
cp LICENSE %{buildroot}/usr/share/license/libsecurity-server-client
%make_install

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

%postun
systemctl daemon-reload

%post -n libsecurity-server-client -p /sbin/ldconfig

%postun -n libsecurity-server-client -p /sbin/ldconfig

%files -n security-server
%manifest %{name}.manifest
%defattr(-,root,root,-)
/usr/lib/systemd/system/multi-user.target.wants/security-server.service
/usr/lib/systemd/system/security-server.service
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
