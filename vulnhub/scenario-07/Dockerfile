FROM debian:11
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y apache2 libapache2-mod-php php php-mysql mariadb-server && apt-get clean && rm -rf /var/lib/apt/lists/*
# Simulate vulnerable Drupal database.inc
RUN mkdir -p /var/www/html/includes/database
RUN cat > /var/www/html/includes/database/database.inc << 'PHPEOF'
<?php
// VULNERABLE: expandArguments does not sanitize array keys
function expandArguments(&$query, &$args) {
  $modified = array();
  foreach (array_filter($args, 'is_array') as $key => $data) {
    $new_keys = array();
    foreach ($data as $i => $value) {
      $new_keys[$key . '_' . $i] = $value;
    }
    $query = preg_replace('#' . $key . '\b#', implode(', ', array_keys($new_keys)), $query);
    unset($args[$key]);
    $modified = $modified + $new_keys;
  }
  return $modified;
}
?>
PHPEOF
EXPOSE 80
COPY verify.sh /verify.sh
CMD service mariadb start && apachectl -D FOREGROUND
