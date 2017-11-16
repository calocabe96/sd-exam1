
bash 'add repo' do
  user 'root'
  code <<-EOH
  yum makecache fast
  rpm --import http://packages.elastic.co/GPG-KEY-elasticsearch
  EOH
end

include_recipe 'filebeat::file_copy_files1'


bash 'install' do
  user 'root'
  code <<-EOH
  yum -y install filebeat
  EOH
end

include_recipe 'filebeat::file_copy_files2'

bash 'start service' do
  user 'root'
  code <<-EOH
  systemctl daemon-reload
  systemctl start filebeat
  systemctl enable filebeat
  systemctl restart network
  EOH
end


