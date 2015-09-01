# Spec file for SCLP kernel module on Red Hat Enterprise Linux 6.
#
# Copyright (C) 2015 Nagoya Institute of Technology
#
# Copying and distribution of this file, with or without modification,
# are permitted in any medium without royalty provided the copyright
# notice and this notice are preserved.  This file is offered as-is,
# without warranty of any kind.

%define modname sclp
%define version 0.1.0
%define release 1

Name:           %{modname}
Version:        %{version}
Release:        %{release}
Summary:        SCLP kernel module

Group:          System/Kernel
License:        GPLv2
URL:            https://github.com/sdnnit/sclp
Source:         %{modname}.tar.gz
BuildRoot:      %(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
BuildRequires:  %kernel_module_package_buildreqs


%define debug_package %{nil}

# Use -D 'kversion 2.6.32-573.3.1.el6.x86_64' to build package
# for specified kernel version.
%{!?kversion: %define kversion %{expand:%%(uname -r;)}}

%description
SCLP kernel module.

%prep

%setup -n %{modname}
cat > %{modname}.conf << EOF
override %{modname} * extra/%{modname}
EOF

%build
make

%install
export INSTALL_MOD_PATH=$RPM_BUILD_ROOT
export INSTALL_MOD_DIR=extra/%{modname}

make modules_install M="`pwd`"
cp Module.symvers $INSTALL_MOD_PATH/lib/modules/`uname -r`/extra/%{modname}
rm -f $RPM_BUILD_ROOT/lib/modules/`uname -r`/modules.*

install -d %{buildroot}%{_sysconfdir}/depmod.d/
install -m 644 %{modname}.conf %{buildroot}%{_sysconfdir}/depmod.d/

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(644,root,root,755)
%config /etc/depmod.d/%{modname}.conf
/lib/modules/%{kversion}/extra/%{modname}/%{modname}.ko
/lib/modules/%{kversion}/extra/%{modname}/Module.symvers
