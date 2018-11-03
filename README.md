# akashvani

This is a demo project that serves as an application gateway for Web Services. Combines the features of a WAF and an API gateway.

## Steps to install on Ubuntu 18

The Security Gateway implementation is an open resty plugin. We need to install open resty and redis before we proceed further.

### Install Open Resty
    
    wget -qO - https://openresty.org/package/pubkey.gpg | sudo apt-key add -
    sudo apt-get -y install software-properties-common
    sudo add-apt-repository -y "deb http://openresty.org/package/ubuntu $(lsb_release -sc) main"
    sudo apt-get update
    sudo apt-get install openresty
    
### Install Redis
    
    sudo apt update
    sudo apt install redis-server
    
Open Browser and visit http://localhost
You should see Open resty welcome Page

### Install the NGINX Configuration and Lua Plugin
Objective of this step is to restart nginx with our new nginx.conf file. 
The new nginx configuration will load the LUA hooks from the plugins folder.

Checkout the project in a local folder.

    $ git clone https://github.com/dseventh/akashvani.git
    $ cd conf

Take a backup of the existing nginx.conf file.

    $ sudo mv /usr/local/openresty/nginx/conf/nginx.conf /usr/local/openresty/nginx/conf/nginx_old.conf 

Update the below like in the plugin/nginx.conf file. This will specify the path of the plugin folder.

    lua_package_path '<PATH_TO_SOURCE>/plugin/?.lua;;;;';
     
Replace the updated plugin/nginx.conf file in the config path
    
    $ sudo cp /<PATH_TO_SOURCE>/conf/nginx.conf /usr/local/openresty/nginx/conf
    
Restart Open Resty Service or Reboot the System


## Steps to Verify installation

    curl htp://localhost:9001/load
     

In the browser goto

    http://localhost:9001/home
    http://localhost:9001/showroutes
    
    This will also verift that the connectivity to redis is working. 
    
    NOTE: Redis is hardcoded/assumed to be available at localhost:6379
    
  
    
    




