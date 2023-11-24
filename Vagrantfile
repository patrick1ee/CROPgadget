# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  config.vm.define "box" do |box|
                box.vm.box = "ubuntu/bionic64"
                box.vm.hostname = "lab4-box"
                box.vm.provider "virtualbox" do |virtualbox|
        virtualbox.name="lab4-box"
    end
    config.vm.provision "shell", inline: "sudo apt-get update --yes"
    config.vm.provision "shell", inline: "sudo apt install -y python3-pip gdb gcc-multilib"
    config.vm.provision "shell", inline: "pip3 install capstone"
    config.vm.provision "shell", inline: "pip3 install pygdbmi"
    
 end
end