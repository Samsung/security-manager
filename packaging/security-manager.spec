Name:       security-manager
Summary:    Security manager and utilities
Version:    0.1.0
Release:    1
Group:      Security/Service
License:    Apache-2.0
Source0:    %{name}-%{version}.tar.gz
Source1:    security-manager.manifest
Source3:    libsecurity-manager-client.manifest
Requires(post): smack
BuildRequires: cmake
BuildRequires: zip
BuildRequires: pkgconfig(dlog)
BuildRequires: libattr-devel
BuildRequires: libcap-devel
BuildRequires: pkgconfig(libsmack)
BuildRequires: pkgconfig(libprivilege-control)
BuildRequires: pkgconfig(libsystemd-daemon)
BuildRequires: pkgconfig(libsystemd-journal)
BuildRequires: pkgconfig(libtzplatform-config)
BuildRequires: pkgconfig(sqlite3)
BuildRequires: pkgconfig(db-util)
BuildRequires: boost-devel
%{?systemd_requires}

%description
Tizen security manager and utilities

%package -n libsecurity-manager-client
Summary:    Security manager (client)
Group:      Security/Libraries
Requires:   security-manager = %{version}-%{release}
Requires(post): /sbin/ldconfig
Requires(postun): /sbin/ldconfig

%description -n libsecurity-manager-client
Tizen Security manager client library

%package -n libsecurity-manager-client-devel
Summary:    Security manager (client-devel)
Group:      Security/Development
Requires:   libsecurity-manager-client = %{version}-%{release}

%description -n libsecurity-manager-client-devel
Development files needed for using the security manager client

%prep
%setup -q
cp %{SOURCE1} .
cp %{SOURCE3} .

%build
%if 0%{?sec_build_binary_debug_enable}
export CFLAGS="$CFLAGS -DTIZEN_DEBUG_ENABLE"
export CXXFLAGS="$CXXFLAGS -DTIZEN_DEBUG_ENABLE"
export FFLAGS="$FFLAGS -DTIZEN_DEBUG_ENABLE"
%endif

export LDFLAGS+="-Wl,--rpath=%{_libdir}"

%cmake . -DVERSION=%{version} \
        -DBIN_INSTALL_DIR=%{_bindir} \
        -DDB_INSTALL_DIR=%{TZ_SYS_DB} \
        -DSYSTEMD_INSTALL_DIR=%{_unitdir} \
        -DCMAKE_BUILD_TYPE=%{?build_type:%build_type}%{!?build_type:RELEASE} \
        -DCMAKE_VERBOSE_MAKEFILE=ON
make %{?jobs:-j%jobs}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/share/license
cp LICENSE %{buildroot}/usr/share/license/%{name}
cp LICENSE %{buildroot}/usr/share/license/libsecurity-manager-client
mkdir -p %{buildroot}/%{TZ_SYS_SMACK}
cp app-rules-template.smack %{buildroot}/%{TZ_SYS_SMACK}
%make_install

mkdir -p %{buildroot}/%{_unitdir}/multi-user.target.wants
mkdir -p %{buildroot}/%{_unitdir}/sockets.target.wants
ln -s ../security-manager.service %{buildroot}/%{_unitdir}/multi-user.target.wants/security-manager.service
ln -s ../security-manager-installer.socket %{buildroot}/%{_unitdir}/sockets.target.wants/security-manager-installer.socket

%clean
rm -rf %{buildroot}

%post
/sbin/ldconfig
systemctl daemon-reload
if [ $1 = 1 ]; then
    # installation
    systemctl start security-manager.service
fi

if [ $1 = 2 ]; then
    # update
    systemctl restart security-manager.service
fi
chsmack -a System %{TZ_SYS_DB}/.security-manager.db
chsmack -a System %{TZ_SYS_DB}/.security-manager.db-journal

%preun
if [ $1 = 0 ]; then
    # unistall
    systemctl stop security-manager.service
fi

%postun
/sbin/ldconfig
if [ $1 = 0 ]; then
    # unistall
    systemctl daemon-reload
fi

%post -n libsecurity-manager-client -p /sbin/ldconfig

%postun -n libsecurity-manager-client -p /sbin/ldconfig

%files -n security-manager
%manifest security-manager.manifest
%defattr(-,root,root,-)
%attr(755,root,root) %{_bindir}/security-manager
%{_libdir}/libsecurity-manager-commons.so.*
%attr(-,root,root) %{_unitdir}/multi-user.target.wants/security-manager.service
%attr(-,root,root) %{_unitdir}/security-manager.service
%attr(-,root,root) %{_unitdir}/security-manager.target
%attr(-,root,root) %{_unitdir}/sockets.target.wants/security-manager-installer.socket
%attr(-,root,root) %{_unitdir}/security-manager-installer.socket
%attr(-,root,root) %{TZ_SYS_SMACK}/app-rules-template.smack
%config(noreplace) %attr(0600,root,root) %{TZ_SYS_DB}/.security-manager.db
%config(noreplace) %attr(0600,root,root) %{TZ_SYS_DB}/.security-manager.db-journal
%{_datadir}/license/%{name}

%files -n libsecurity-manager-client
%manifest libsecurity-manager-client.manifest
%defattr(-,root,root,-)
%{_libdir}/libsecurity-manager-client.so.*
%{_datadir}/license/libsecurity-manager-client

%files -n libsecurity-manager-client-devel
%manifest %{name}.manifest
%defattr(-,root,root,-)
%{_libdir}/libsecurity-manager-client.so
%{_libdir}/libsecurity-manager-commons.so
%{_includedir}/security-manager/security-manager.h
%{_libdir}/pkgconfig/security-manager.pc
