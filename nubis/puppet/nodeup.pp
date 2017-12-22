$nodeup_version='1.8.0'
$nodeup_url="https://kubeupv2.s3.amazonaws.com/kops/${nodeup_version}/linux/amd64/nodeup"

file {'/var/cache/kubernetes-install':
  ensure => directory,
  owner  => root,
  group  => root,
  mode   => '0755',
}

notice ("Grabbing nodeup ${nodeup_version}")
staging::file { "nodeup.${nodeup_version}":
  source => $nodeup_url,
  target => '/usr/local/bin/nodeup',
  owner  => 'root',
  group  => 'root',
  mode   => '0755',
}

systemd::unit_file { 'kops-configuration.service':
  source => 'puppet:///nubis/files/kops-configuration.systemd',
}->
service { 'kops-configuration':
  enable => true,
}

file { '/etc/nubis.d/kops':
    ensure => file,
    owner  => root,
    group  => root,
    mode   => '0755',
    source => 'puppet:///nubis/files/startup',
}
