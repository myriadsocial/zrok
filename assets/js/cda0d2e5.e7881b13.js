"use strict";(self.webpackChunkwebsite=self.webpackChunkwebsite||[]).push([[846],{9836:(e,n,r)=>{r.r(n),r.d(n,{assets:()=>k,contentTitle:()=>b,default:()=>y,frontMatter:()=>j,metadata:()=>g,toc:()=>v});var s=r(5893),i=r(1151),t=r(7294),o=r(4866),a=r(5518);const l=function(e){const[n,r]=(0,t.useState)(null);return(0,t.useEffect)((()=>{["Mac OS","Windows","Linux"].includes(a.BF)?r(a.BF):r("Linux")}),[]),(0,s.jsx)(s.Fragment,{children:(0,s.jsx)(o.Z,{...e,defaultValue:n,children:e.children})})};var c=r(5162),d=r(1326),h=r(2753);function p(e){const n={a:"a",code:"code",h2:"h2",h3:"h3",li:"li",ol:"ol",p:"p",pre:"pre",ul:"ul",...(0,i.a)(),...e.components},{Details:r}=n;return r||function(e,n){throw new Error("Expected "+(n?"component":"object")+" `"+e+"` to be defined: you likely forgot to import, pass, or provide it.")}("Details",!0),(0,s.jsxs)(s.Fragment,{children:[(0,s.jsx)(n.h2,{id:"goal",children:"Goal"}),"\n",(0,s.jsx)(n.p,{children:"Proxy a reserved public subdomain to a backend target with an always-on Linux system service."}),"\n",(0,s.jsx)(n.h2,{id:"how-it-works",children:"How it Works"}),"\n",(0,s.jsxs)(n.p,{children:["The ",(0,s.jsx)(n.code,{children:"zrok-share"})," package creates a ",(0,s.jsx)(n.code,{children:"zrok-share.service"})," unit in systemd. The administrator edits the service's configuration file to specify the:"]}),"\n",(0,s.jsxs)(n.ol,{children:["\n",(0,s.jsx)(n.li,{children:"zrok environment enable token"}),"\n",(0,s.jsxs)(n.li,{children:["target URL or files to be shared and backend mode, e.g. ",(0,s.jsx)(n.code,{children:"proxy"})]}),"\n",(0,s.jsx)(n.li,{children:"authentication options, if wanted"}),"\n"]}),"\n",(0,s.jsx)(n.p,{children:"When the service starts it will:"}),"\n",(0,s.jsxs)(n.ol,{children:["\n",(0,s.jsxs)(n.li,{children:["enable the zrok environment unless ",(0,s.jsx)(n.code,{children:"/var/lib/zrok-share/.zrok/environment.json"})," exists"]}),"\n",(0,s.jsxs)(n.li,{children:["reserve a public subdomain for the service unless ",(0,s.jsx)(n.code,{children:"/var/lib/zrok-share/.zrok/reserved.json"})," exists"]}),"\n",(0,s.jsxs)(n.li,{children:["start sharing the target specified as ",(0,s.jsx)(n.code,{children:"ZROK_TARGET"})," in the environment file"]}),"\n"]}),"\n",(0,s.jsx)(n.h2,{id:"installation",children:"Installation"}),"\n",(0,s.jsxs)(n.ol,{children:["\n",(0,s.jsxs)(n.li,{children:["\n",(0,s.jsxs)(n.p,{children:["Set up ",(0,s.jsx)(n.code,{children:"zrok"}),"'s Linux package repository by following ",(0,s.jsx)(n.a,{href:"/docs/guides/install/linux#install-zrok-from-the-repository",children:"the Linux install guide"}),", or run this one-liner to complete the repo setup and install packages."]}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",children:"curl -sSLf https://get.openziti.io/install.bash \\\n| sudo bash -s zrok-share\n"})}),"\n"]}),"\n",(0,s.jsxs)(n.li,{children:["\n",(0,s.jsxs)(n.p,{children:["If you set up the repository by following the guide, then also install the ",(0,s.jsx)(n.code,{children:"zrok-share"})," package. This package provides the systemd service."]}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",metastring:'title="Ubuntu, Debian"',children:"sudo sudo apt install zrok-share\n"})}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",metastring:'title="Fedora, Rocky"',children:"sudo dnf install zrok-share\n"})}),"\n"]}),"\n"]}),"\n",(0,s.jsxs)(r,{children:[(0,s.jsx)("summary",{children:"Ansible Playbook"}),(0,s.jsxs)(h.Z,{title:"Set up package repository and install zrok-share",children:[d.Z,"\n- name: Install zrok-share package\n  gather_facts: false\n  hosts: all \n  become: true\n  tasks:\n  - name: Install zrok-share\n    ansible.builtin.package:\n      name: zrok-share\n      state: present\n\n  - name: Copy env config from Ansible controller to target\n    copy:\n      dest: /opt/openziti/etc/zrok/zrok-share.env\n      src: /opt/openziti/etc/zrok/zrok-share.env\n\n  - name: Enable and restart service\n    systemd:\n      name: zrok-share\n      enabled: yes\n      state: restarted\n      daemon_reload: yes\n\n  - name: Wait for service\n    systemd:\n      name: zrok-share\n      state: started\n    register: service_status\n    until: service_status.status.ActiveState == 'active'\n    retries: 30\n    delay: 1\n"]})]}),"\n",(0,s.jsx)(n.h2,{id:"enable",children:"Enable"}),"\n",(0,s.jsx)(n.p,{children:"Save the enable token from the zrok console in the configuration file."}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",metastring:'title="/opt/openziti/etc/zrok/zrok-share.env"',children:'ZROK_ENABLE_TOKEN="14cbfca9772f"\n'})}),"\n",(0,s.jsx)(n.h2,{id:"use-cases",children:"Use Cases"}),"\n",(0,s.jsxs)(n.p,{children:["You may change the target for the current backend mode, e.g. ",(0,s.jsx)(n.code,{children:"proxy"}),", by editing the configuration file and restarting the service. The reserved subdomain will remain the same."]}),"\n",(0,s.jsxs)(n.p,{children:["You may switch between backend modes or change authentication options by deleting ",(0,s.jsx)(n.code,{children:"/var/lib/zrok-share/.zrok/reserved.json"})," and restarting the service. A new subdomain will be reserved."]}),"\n",(0,s.jsx)(n.h3,{id:"proxy-a-web-server",children:"Proxy a Web Server"}),"\n",(0,s.jsx)(n.p,{children:"Proxy a reserved subdomain to an existing web server. The web server could be on a private network or on the same host as zrok."}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",metastring:'title="/opt/openziti/etc/zrok/zrok-share.env"',children:'ZROK_TARGET="http://127.0.0.1:3000"\nZROK_BACKEND_MODE="proxy"\n'})}),"\n",(0,s.jsxs)(n.p,{children:["If your HTTPS server has an unverifiable TLS server certificate then you must set ",(0,s.jsx)(n.code,{children:"--insecure"}),"."]}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",metastring:'title="/opt/openziti/etc/zrok/zrok-share.env"',children:'ZROK_INSECURE="--insecure"\n'})}),"\n",(0,s.jsx)(n.h3,{id:"serve-static-files",children:"Serve Static Files"}),"\n",(0,s.jsxs)(n.p,{children:["Run zrok's embedded web server to serve the files in a directory. If there's an ",(0,s.jsx)(n.code,{children:"index.html"})," file in the directory then visitors will see that web page in their browser, otherwise they'll see a generated index of the files. The directory must be readable by 'other', e.g. ",(0,s.jsx)(n.code,{children:"chmod -R o+rX /var/www/html"}),"."]}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",metastring:'title="/opt/openziti/etc/zrok/zrok-share.env"',children:'ZROK_TARGET="/var/www/html"\nZROK_BACKEND_MODE="web"\n'})}),"\n",(0,s.jsx)(n.h3,{id:"caddy-server",children:"Caddy Server"}),"\n",(0,s.jsx)(n.p,{children:"Use zrok's built-in Caddy server to serve static files or as a reverse proxy to multiple web servers with various HTTP routes or as a load-balanced set. A sample Caddyfile is available in the path shown."}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",metastring:'title="/opt/openziti/etc/zrok/zrok-share.env"',children:'ZROK_TARGET="/opt/openziti/etc/zrok/multiple_upstream.Caddyfile"\nZROK_BACKEND_MODE="caddy"\n'})}),"\n",(0,s.jsx)(n.h3,{id:"network-drive",children:"Network Drive"}),"\n",(0,s.jsxs)(n.p,{children:["This uses zrok's ",(0,s.jsx)(n.code,{children:"drive"})," backend mode to serve a directory of static files as a virtual network drive. The directory must be readable by 'other', e.g. ",(0,s.jsx)(n.code,{children:"chmod -R o+rX /usr/share/doc"}),"."]}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",metastring:'title="/opt/openziti/etc/zrok/zrok-share.env"',children:'ZROK_TARGET="/usr/share/doc"\nZROK_BACKEND_MODE="drive"\n'})}),"\n",(0,s.jsxs)(n.p,{children:[(0,s.jsx)(n.a,{href:"https://blog.openziti.io/zrok-drives-an-early-preview",children:"Learn more about this feature in this blog post"}),"."]}),"\n",(0,s.jsx)(n.h2,{id:"authentication",children:"Authentication"}),"\n",(0,s.jsx)(n.p,{children:"You can limit access to certain email addresses with OAuth or require a password."}),"\n",(0,s.jsx)(n.h3,{id:"oauth",children:"OAuth"}),"\n",(0,s.jsx)(n.p,{children:"You can require that visitors authenticate with an email address that matches at least one of the suffixes you specify. Add the following to the configuration file."}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",metastring:'title="/opt/openziti/etc/zrok/zrok-share.env"',children:'ZROK_OAUTH_PROVIDER="github"  # or google\nZROK_OAUTH_EMAILS="bob@example.com @acme.example.com"\n'})}),"\n",(0,s.jsx)(n.h3,{id:"password",children:"Password"}),"\n",(0,s.jsx)(n.p,{children:"Enable HTTP basic authentication by adding the following to the configuration file."}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",metastring:'title="/opt/openziti/etc/zrok/zrok-share.env"',children:'ZROK_BASIC_AUTH="user:passwd"\n'})}),"\n",(0,s.jsx)(n.h2,{id:"start-the-service",children:"Start the Service"}),"\n",(0,s.jsx)(n.p,{children:"Start the service, and check the zrok console or the service log for the reserved subdomain."}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",metastring:'title="run now and at startup"',children:"sudo systemctl enable --now zrok-share.service\n"})}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",metastring:'title="run now"',children:"sudo systemctl restart zrok-share.service\n"})}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",children:"journalctl -u zrok-share.service\n"})}),"\n",(0,s.jsx)(n.h2,{id:"compatibility",children:"Compatibility"}),"\n",(0,s.jsxs)(n.p,{children:["The Linux distribution must have a package manager that understands the ",(0,s.jsx)(n.code,{children:".deb"})," or ",(0,s.jsx)(n.code,{children:".rpm"})," format and be running systemd v232 or newer. The service was tested with:"]}),"\n",(0,s.jsxs)(n.ul,{children:["\n",(0,s.jsx)(n.li,{children:"Ubuntu 20.04, 22.04, 23.04"}),"\n",(0,s.jsx)(n.li,{children:"Debian 11 12"}),"\n",(0,s.jsx)(n.li,{children:"Rocky 8, 9"}),"\n",(0,s.jsx)(n.li,{children:"Fedora 37, 38"}),"\n"]}),"\n",(0,s.jsx)(n.h2,{id:"package-contents",children:"Package Contents"}),"\n",(0,s.jsxs)(n.p,{children:["The files included in the ",(0,s.jsx)(n.code,{children:"zrok-share"})," package are sourced ",(0,s.jsx)(n.a,{href:"https://github.com/openziti/zrok/tree/main/nfpm",children:"here in GitHub"}),"."]})]})}function u(e={}){const{wrapper:n}={...(0,i.a)(),...e.components};return n?(0,s.jsx)(n,{...e,children:(0,s.jsx)(p,{...e})}):p(e)}function m(e){const n={a:"a",code:"code",h2:"h2",h3:"h3",li:"li",ol:"ol",p:"p",pre:"pre",...(0,i.a)(),...e.components};return(0,s.jsxs)(s.Fragment,{children:[(0,s.jsx)(n.h2,{id:"goal",children:"Goal"}),"\n",(0,s.jsx)(n.p,{children:"Proxy a reserved public subdomain to a backend target with an always-on Docker Compose service."}),"\n",(0,s.jsx)(n.h2,{id:"how-it-works",children:"How it Works"}),"\n",(0,s.jsx)(n.p,{children:"The Docker Compose project uses your zrok account token to reserve a public subdomain and keep sharing the backend\ntarget."}),"\n",(0,s.jsx)(n.p,{children:"When the project runs it will:"}),"\n",(0,s.jsxs)(n.ol,{children:["\n",(0,s.jsxs)(n.li,{children:["enable a zrok environment unless ",(0,s.jsx)(n.code,{children:"/mnt/.zrok/environment.json"})," exists in the ",(0,s.jsx)(n.code,{children:"zrok_env"})," volume"]}),"\n",(0,s.jsxs)(n.li,{children:["reserve a public subdomain for the service unless ",(0,s.jsx)(n.code,{children:"/mnt/.zrok/reserved.json"})," exists"]}),"\n",(0,s.jsxs)(n.li,{children:["start sharing the target specified in the ",(0,s.jsx)(n.code,{children:"ZROK_TARGET"})," environment variable"]}),"\n"]}),"\n",(0,s.jsx)(n.h2,{id:"create-the-docker-project",children:"Create the Docker Project"}),"\n",(0,s.jsxs)(n.ol,{children:["\n",(0,s.jsx)(n.li,{children:"Make a folder on your computer to use as a Docker Compose project for your zrok public share with a reserved subdomain and switch to the new directory in your terminal."}),"\n",(0,s.jsxs)(n.li,{children:["Download ",(0,s.jsxs)(n.a,{href:"pathname:///zrok-public-reserved/compose.yml",children:["the reserved public share ",(0,s.jsx)(n.code,{children:"compose.yml"})," project file"]})," into the same directory."]}),"\n",(0,s.jsxs)(n.li,{children:["Copy your zrok account's enable token from the zrok web console to your clipboard and paste it in a file named ",(0,s.jsx)(n.code,{children:".env"})," in the same folder like this:"]}),"\n"]}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",metastring:'title=".env"',children:'ZROK_ENABLE_TOKEN="8UL9-48rN0ua"\n'})}),"\n",(0,s.jsxs)(n.ol,{children:["\n",(0,s.jsxs)(n.li,{children:["Run the Compose project to start sharing the built-in demo web server. Be sure to ",(0,s.jsx)(n.code,{children:"--detach"})," so the project runs in the background if you want it to auto-restart when your computer reboots."]}),"\n"]}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",children:"docker compose up --detach\n"})}),"\n",(0,s.jsxs)(n.ol,{children:["\n",(0,s.jsxs)(n.li,{children:["Get the public share URL from the output of the ",(0,s.jsx)(n.code,{children:"zrok-share"})," service or by peeking in the zrok console where the share will appear in the graph."]}),"\n"]}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",children:"docker compose logs zrok-share\n"})}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-buttonless",metastring:'title="Output"',children:"zrok-public-share-1  |  https://w6r1vesearkj.in.zrok.io/\n"})}),"\n",(0,s.jsx)(n.p,{children:"This concludes the minimum steps to begin sharing the demo web server. Read on to learn how to pivot to sharing any website or web service by leveraging additional zrok backend modes."}),"\n",(0,s.jsx)(n.h2,{id:"proxy-any-web-server",children:"Proxy Any Web Server"}),"\n",(0,s.jsxs)(n.p,{children:["The simplest way to share your existing HTTP server is to set ",(0,s.jsx)(n.code,{children:"ZROK_TARGET"})," (e.g. ",(0,s.jsx)(n.code,{children:"https://example.com"}),") in the environment of the ",(0,s.jsx)(n.code,{children:"docker compose up"})," command. When you restart the share will auto-configure for that URL."]}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",metastring:'title=".env"',children:'ZROK_TARGET="http://example.com:8080"\n'})}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",children:"docker compose down && docker compose up\n"})}),"\n",(0,s.jsx)(n.h2,{id:"require-authentication",children:"Require Authentication"}),"\n",(0,s.jsx)(n.p,{children:"You can require a password or an OAuth login with certain email addresses."}),"\n",(0,s.jsx)(n.h3,{id:"oauth-email",children:"OAuth Email"}),"\n",(0,s.jsxs)(n.p,{children:["You can allow specific email addresses or an email domain by setting ",(0,s.jsx)(n.code,{children:"ZROK_OAUTH_PROVIDER"})," to ",(0,s.jsx)(n.code,{children:"github"})," or ",(0,s.jsx)(n.code,{children:"google"})," and\n",(0,s.jsx)(n.code,{children:"ZROK_SHARE_OPTS"})," to specify additional command-line options to ",(0,s.jsx)(n.code,{children:"zrok reserve public"}),". Read more about the OAuth\nfeatures in ",(0,s.jsx)(n.a,{href:"https://blog.openziti.io/the-zrok-oauth-public-frontend",children:"this blog post"}),"."]}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",metastring:'title=".env"',children:'ZROK_OAUTH_PROVIDER="github"\nZROK_SHARE_OPTS="--oauth-email-domains @example.com"\n'})}),"\n",(0,s.jsx)(n.h2,{id:"caddy-is-powerful",children:"Caddy is Powerful"}),"\n",(0,s.jsxs)(n.p,{children:["The reserved public share project uses zrok's default backend mode, ",(0,s.jsx)(n.code,{children:"proxy"}),". Another backend mode, ",(0,s.jsx)(n.code,{children:"caddy"}),", accepts a path to ",(0,s.jsx)(n.a,{href:"https://caddyserver.com/docs/caddyfile",children:"a Caddyfile"})," as the value of ",(0,s.jsx)(n.code,{children:"ZROK_TARGET"})," (",(0,s.jsx)(n.a,{href:"https://github.com/openziti/zrok/tree/main/etc/caddy",children:"zrok Caddyfile examples"}),")."]}),"\n",(0,s.jsxs)(n.p,{children:["Caddy is the most powerful and flexible backend mode in zrok. You must reserve a new public subdomain whenever you switch the backend mode, so using ",(0,s.jsx)(n.code,{children:"caddy"})," reduces the risk that you'll have to share a new frontend URL with your users."]}),"\n",(0,s.jsx)(n.p,{children:"With Caddy, you can balance the workload for websites or web services or share static sites and files or all of the above at the same time. You can update the Caddyfile and restart the Docker Compose project to start sharing the new configuration with the same reserved public subdomain."}),"\n",(0,s.jsxs)(n.ol,{children:["\n",(0,s.jsx)(n.li,{children:"Create a Caddyfile. This example demonstrates proxying two HTTP servers with a weighted round-robin load balancer."}),"\n"]}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-console",metastring:'title="Caddyfile"',children:"http:// {\n  # zrok requires this bind address template\n  bind {{ .ZrokBindAddress }}\n  reverse_proxy /* {\n    to http://httpbin1:8080 http://httpbin2:8080\n    lb_policy weighted_round_robin 3 2\n  }\n}\n"})}),"\n",(0,s.jsxs)(n.ol,{children:["\n",(0,s.jsxs)(n.li,{children:["Create a file ",(0,s.jsx)(n.code,{children:"compose.override.yml"}),". This example adds two ",(0,s.jsx)(n.code,{children:"httpbin"})," containers for load balancing, and mounts the Caddyfile into the container."]}),"\n"]}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-yaml",metastring:'title="compose.override.yml"',children:"services:\n  httpbin1:\n    image: mccutchen/go-httpbin  # 8080/tcp\n  httpbin2:\n    image: mccutchen/go-httpbin  # 8080/tcp\n  zrok-share:\n    volumes:\n      - ./Caddyfile:/mnt/.zrok/Caddyfile\n"})}),"\n",(0,s.jsxs)(n.ol,{children:["\n",(0,s.jsx)(n.li,{children:"Start a new Docker Compose project or delete the existing state volume."}),"\n"]}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",children:"docker compose down --volumes\n"})}),"\n",(0,s.jsxs)(n.p,{children:["If you prefer to keep using the same zrok environment with the new share then delete ",(0,s.jsx)(n.code,{children:"/mnt/.zrok/reserved.json"})," instead of the entire volume."]}),"\n",(0,s.jsxs)(n.ol,{children:["\n",(0,s.jsx)(n.li,{children:"Run the project to load the new configuration."}),"\n"]}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",children:"docker compose up --detach\n"})}),"\n",(0,s.jsxs)(n.ol,{children:["\n",(0,s.jsx)(n.li,{children:"Note the new reserved share URL from the log."}),"\n"]}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-bash",children:"docker compose logs zrok-share\n"})}),"\n",(0,s.jsx)(n.pre,{children:(0,s.jsx)(n.code,{className:"language-buttonless",metastring:'title="Output"',children:"INFO: zrok public URL: https://88s803f2qvao.in.zrok.io/\n"})})]})}function x(e={}){const{wrapper:n}={...(0,i.a)(),...e.components};return n?(0,s.jsx)(n,{...e,children:(0,s.jsx)(m,{...e})}):m(e)}const j={title:"zrok frontdoor",sidebar_label:"frontdoor",sidebar_position:20},b=void 0,g={id:"guides/frontdoor",title:"zrok frontdoor",description:"zrok frontdoor provides a shielded entry point for your production website or service. This is useful if you want to expose it to the public internet, but not directly.",source:"@site/../docs/guides/frontdoor.mdx",sourceDirName:"guides",slug:"/guides/frontdoor",permalink:"/docs/guides/frontdoor",draft:!1,unlisted:!1,editUrl:"https://github.com/openziti/zrok/blob/main/docs/../docs/guides/frontdoor.mdx",tags:[],version:"current",sidebarPosition:20,frontMatter:{title:"zrok frontdoor",sidebar_label:"frontdoor",sidebar_position:20},sidebar:"tutorialSidebar",previous:{title:"Windows",permalink:"/docs/guides/install/windows"},next:{title:"Docker Share",permalink:"/docs/category/docker-share"}},k={},v=[{value:"Concepts",id:"concepts",level:2}];function f(e){const n={a:"a",code:"code",h2:"h2",p:"p",strong:"strong",...(0,i.a)(),...e.components};return(0,s.jsxs)(s.Fragment,{children:[(0,s.jsxs)(n.p,{children:[(0,s.jsx)(n.strong,{children:"zrok frontdoor"})," provides a shielded entry point for your production website or service. This is useful if you want to expose it to the public internet, but not directly."]}),"\n",(0,s.jsxs)(l,{queryString:"os",values:[{label:"Linux",value:"Linux"},{label:"macOS",value:"Mac OS"},{label:"Windows",value:"Windows"}],children:[(0,s.jsxs)(c.Z,{value:"Linux",children:[(0,s.jsxs)(n.p,{children:["On Linux, zrok frontdoor is implemented natively as a system service provided by the ",(0,s.jsx)(n.code,{children:"zrok-share"})," DEB or RPM package."]}),(0,s.jsxs)(n.p,{children:["If you'd prefer to run zrok in Docker, you can follow the same Docker instructions for ",(0,s.jsx)(n.a,{href:"./?os=Mac+OS",children:"macOS"})," or ",(0,s.jsx)(n.a,{href:"./?os=Windows",children:"Windows"}),"."]}),(0,s.jsx)(u,{})]}),(0,s.jsxs)(c.Z,{value:"Mac OS",children:[(0,s.jsx)(n.p,{children:"On macOS, zrok frontdoor is implemented as a Docker Compose project which reserves a public subdomain for your website or service."}),(0,s.jsx)(x,{})]}),(0,s.jsxs)(c.Z,{value:"Windows",children:[(0,s.jsx)(n.p,{children:"On Windows, zrok frontdoor is implemented as a Docker Compose project which reserves a public subdomain for your website or service."}),(0,s.jsx)(x,{})]})]}),"\n",(0,s.jsx)(n.h2,{id:"concepts",children:"Concepts"}),"\n",(0,s.jsxs)(n.p,{children:["Overview of ",(0,s.jsx)(n.a,{href:"/docs/concepts/sharing-reserved",children:"zrok reserved shares"})]})]})}function y(e={}){const{wrapper:n}={...(0,i.a)(),...e.components};return n?(0,s.jsx)(n,{...e,children:(0,s.jsx)(f,{...e})}):f(e)}},2753:(e,n,r)=>{r.d(n,{Z:()=>o});r(7294);var s=r(1272),i=r(9286),t=r(5893);const o=e=>{let{title:n,children:r}=e;const o=r.map((e=>"string"==typeof e?e.trim():s.ZP.dump(e).trim())).join("\n\n");return(0,t.jsx)("div",{children:(0,t.jsx)(i.Z,{language:"yaml",title:n,children:o})})}},1326:(e,n,r)=>{r.d(n,{Z:()=>s});const s=[{name:"Set up zrok Package Repo",gather_facts:!0,hosts:"all",become:!0,tasks:[{name:"Set up apt repo",when:'ansible_os_family == "Debian"',block:[{name:"Install playbook dependencies","ansible.builtin.package":{name:["gnupg"],state:"present"}},{name:"Fetch armored pubkey","ansible.builtin.uri":{url:"https://get.openziti.io/tun/package-repos.gpg",return_content:"yes"},register:"armored_pubkey"},{name:"Dearmor pubkey","ansible.builtin.shell":'gpg --dearmor --output /usr/share/keyrings/openziti.gpg <<< "{{ armored_pubkey.content }}"\n',args:{creates:"/usr/share/keyrings/openziti.gpg",executable:"/bin/bash"}},{name:"Set pubkey filemode","ansible.builtin.file":{path:"/usr/share/keyrings/openziti.gpg",mode:"a+rX"}},{name:"Install OpenZiti repo deb source","ansible.builtin.copy":{dest:"/etc/apt/sources.list.d/openziti-release.list",content:"deb [signed-by=/usr/share/keyrings/openziti.gpg] https://packages.openziti.org/zitipax-openziti-deb-stable debian main\n"}},{name:"Refresh Repo Sources","ansible.builtin.apt":{update_cache:"yes",cache_valid_time:3600}}]},{name:"Set up yum repo",when:'ansible_os_family == "RedHat"',block:[{name:"Install OpenZiti repo rpm source","ansible.builtin.yum_repository":{name:"OpenZitiRelease",description:"OpenZiti Release",baseurl:"https://packages.openziti.org/zitipax-openziti-rpm-stable/redhat/$basearch",enabled:"yes",gpgkey:"https://packages.openziti.org/zitipax-openziti-rpm-stable/redhat/$basearch/repodata/repomd.xml.key",repo_gpgcheck:"yes",gpgcheck:"no"}}]}]}]}}]);