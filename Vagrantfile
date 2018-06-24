Vagrant.configure("2") do |config|
  config.vm.box = "bento/debian-9.4"
  config.vm.box_check_update = false

  config.ssh.forward_agent = true

  config.vm.provider "virtualbox" do |vb|
    # Customize the amount of memory on the VM:
    vb.memory = "8192"
    vb.cpus = 4
  end

end
