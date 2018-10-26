Vagrant.configure("2") do |config|
  config.vm.box = "bento/debian-9.4"
  config.vm.box_check_update = false

  config.ssh.forward_agent = true

  config.vm.provider "virtualbox" do |vb|
    # Customize the amount of memory on the VM:
    vb.memory = "8192"
    vb.cpus = 4
    vb.customize ["modifyvm", :id, "--usb", "on"]
    vb.customize ['usbfilter', 'add', '0', '--target', :id, '--name', 'TPM', '--vendorid', '0x10c4', '--productid', '0x8bde']
  end

end
