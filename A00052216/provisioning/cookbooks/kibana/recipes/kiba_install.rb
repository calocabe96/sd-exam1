
bash 'add repo' do
  user 'root'
  code <<-EOH
  yum makecache fast
  yum -y install java
  yum -y install kibana
  EOH
end

include_recipe 'kibana::kiba_copy_files1'

bash 'open port' do
  user 'root'
  code <<-EOH
  systemctl daemon-reload
  systemctl start kibana
  systemctl enable kibana
  systemctl start firewalld
  firewall-cmd --add-port=5601/tcp
  firewall-cmd --add-port=5601/tcp --permanent
  systemctl restart network
  EOH
end


