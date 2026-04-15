# meta3/ubuntu/shared

Vendored Chef resources from [rapid7/metasploitable3](https://github.com/rapid7/metasploitable3) (BSD-3-Clause, commit `b3442cc893fe4fa5a63a8ec95267ab4ee9881c5c`). Used by scenario Dockerfiles to provision the Meta3-Ubuntu software stack (Drupal 7.31, payroll_app, phpMyAdmin, ProFTPD 1.3.5, UnrealIRCd, Samba) at build time via `chef-solo`.

License attribution: [`UPSTREAM_LICENSE`](UPSTREAM_LICENSE) (verbatim upstream `LICENSE` at `UPSTREAM_LICENSE.orig`).

## What's vendored

```
cookbooks/metasploitable/
├── metadata.rb
├── attributes/default.rb
├── recipes/
│   ├── default.rb
│   ├── drupal.rb
│   ├── payroll_app.rb
│   ├── phpmyadmin.rb
│   ├── proftpd.rb
│   ├── samba.rb
│   └── unrealircd.rb
├── templates/payroll_app/payroll.sql.erb
└── files/
    ├── drupal/        (default_site.tar.gz, drupal.sql)
    ├── payroll_app/   (payroll_app.php, poc.rb)
    ├── phpmyadmin/    (config.inc.php)
    ├── proftpd/       (init script, Upstart conf, renewer helpers)
    ├── samba/         (passdb.tdb, smb.conf)
    └── unrealircd/    (unrealircd binary, unrealircd.conf, ircd.motd)
```

## What's NOT vendored

- Rapid7's Vagrantfile, packer templates, and Windows `.bat`/`.ps1` install scripts
- Unrelated cookbooks (apache_continuum, chatbot, cups, flags, knockd, readme_app, sinatra, sshd) — either not used by meta3-ubuntu scenarios or already covered by sibling suites
- The `users.rb` recipe (Star-Wars-named accounts) — not needed; scenarios that require specific users create them in their own Dockerfile

## Patches applied to the vendored copy

1. **`attributes/default.rb`** — `files_path` changed from `/vagrant/chef/cookbooks/metasploitable/files/` to `/cookbooks/metasploitable/files/` so recipes resolve under the container's `COPY`ed path. The original line is retained as a comment.

2. **Upstart/service blocks stripped.** Docker containers have no init daemon, so `service '...' do action [:enable, :start | :restart] end` blocks would fail. The following recipes had their service blocks commented out:
   - `recipes/proftpd.rb` — three `service` blocks removed
   - `recipes/unrealircd.rb` — one `service` block removed
   - `recipes/samba.rb` — one `service` block removed
   - `recipes/phpmyadmin.rb` — one `service 'apache2' { action [:restart] }` removed

   File/template/package/bash resources are left intact. Daemons are started by each scenario's `entrypoint.sh` in the foreground instead.

   Note: `cookbook_file '/etc/init/*.conf'` and `cookbook_file '/etc/init.d/*'` resources are left intact — they just drop files on disk. Without an init daemon they're inert.

## How scenarios use it

Each scenario Dockerfile is built from `meta3/ubuntu/` as the build context:

```bash
cd meta3/ubuntu
docker build -f scenario-06/Dockerfile -t meta3u-s06 .
```

The Dockerfile does:

```dockerfile
COPY shared/cookbooks /cookbooks
COPY scenario-06/solo.rb /solo.rb
COPY scenario-06/scenario.json /scenario.json
RUN chef-solo -c /solo.rb -j /scenario.json
```

`scenario.json` carries the targeted run_list (e.g. `["recipe[metasploitable::drupal]"]`) and any attribute overrides.
