
bash 'add repo' do
  user 'root'
  code <<-EOH
  yum makecache fast
  yum -y install java
  yum -y install logstash
  EOH
end

include_recipe 'logstash::log_copy_files1'

bash 'open port' do
  user 'root'
  code <<-EOH
  systemctl daemon-reload
  systemctl enable logstash
  systemctl start logstash
  systemctl start firewalld
  firewall-cmd --add-port=5044/tcp
  firewall-cmd --add-port=5044/tcp --permanent
  systemctl restart network
  EOH
end


