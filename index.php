<?php


function run() {

    $domain = isset( $_REQUEST['q'] ) ? $_REQUEST['q'] : "";
    $errors = [];

    if ( ! isset( $_REQUEST['q'] ) ) {
        return;
    }

    if ( ! filter_var( $domain, FILTER_VALIDATE_DOMAIN ) ) {
        $errors[] = "Invalid domain.";
    }
    
    if ( filter_var( $domain, FILTER_VALIDATE_DOMAIN ) && strpos( $domain, '.') === false ) {
        $errors[] = "Invalid domain.";
    }

    if (strlen($domain) < 4) {
        $errors[] = "No domain name is that short.";
    }

    if (strlen($domain) > 80) {
        $errors[] = "Too long.";
    }

    if ( count( $errors ) > 0 ) {
        echo json_encode( [
            "errors" => $errors,
          ]);
        die();
    }

    $bash_dns_records = <<<EOT
echo "A records"
dig $domain +short
echo "www $( dig www.$domain +short )"
echo ""
echo "MX records"
dig $domain MX +short
echo ""
echo "TXT records"
dig $domain txt +short
EOT;

    $bash_ip_lookup = <<<EOT
for ip in $( dig $domain +short ); do
    echo "Details on \$ip"
    whois \$ip | grep -E 'NetName:|Organization:|OrgName:'
done
EOT;

  $whois       = shell_exec( "whois $domain | grep -E 'Name Server|Registrar:|Domain Name:|Updated Date:|Creation Date:|Registrar IANA ID:Domain Status:'" );
  $dns_records = shell_exec( $bash_dns_records );
  $ip_lookup   = shell_exec( $bash_ip_lookup );
  echo json_encode( [
    "whois"       => $whois,
    "dns_records" => $dns_records,
    "ip_lookup"   => $ip_lookup,
    "errors"      => [],
  ]);
  die();
}

run();

?><!DOCTYPE html>
<html>
<head>
  <link href="https://fonts.googleapis.com/css?family=Roboto:100,300,400,500,700,900" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/@mdi/font@4.x/css/materialdesignicons.min.css" rel="stylesheet">
  <link href="https://cdn.jsdelivr.net/npm/vuetify@2.x/dist/vuetify.min.css" rel="stylesheet">
  <link rel="icon" href="favicon.png" />
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, minimal-ui">
  <style>
    [v-cloak] > * {
        display:none;
    }
  </style>
</head>
<body>
  <div id="app" v-cloak>
    <v-app>
      <v-main>
        <v-container>
            <v-text-field label="Domain" v-model="domain" spellcheck="false"></v-text-field>
            <v-btn @click="lookupDomain()" class="mb-7">Lookup</v-btn>
            <v-alert type="warning" v-for="error in response.errors">{{ error }}</v-alert>
            <v-row v-if="response.whois && response.whois != ''" class="mt-7">
            <v-col cols="5">
            <v-card>
                <v-card-title>Whois</v-card-title>
                <v-card-text>
                    <pre>{{ response.whois }}</pre>
                </v-card-text>
                </v-card>
                </v-expand-transition>
            </v-card>
            <v-card class="mt-5">
                <v-card-title>IP information</v-card-title>
                <v-card-text>
                    <pre>{{ response.ip_lookup }}</pre>
                </v-card-text>
                </v-card>
                </v-expand-transition>
            </v-card>
            </v-col>
            <v-col cols="7">
            <v-card>
                <v-card-title>Common DNS records</v-card-title>
                <v-card-text>
                    <pre>{{ response.dns_records }}</pre>
                </v-card-text>
                </v-card>
                </v-expand-transition>
            </v-card>
            </v-col>
            </v-row>
        </v-container>
      </v-main>
    </v-app>
  </div>
  <script src="https://cdn.jsdelivr.net/npm/vue@2.x/dist/vue.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/vuetify@2.x/dist/vuetify.js"></script>
  <script>
    new Vue({
        el: '#app',
        vuetify: new Vuetify(),
        data: {
            domain: "",
            response: { whois: "", errors: [] }
        },
        methods: {
            lookupDomain() {
                fetch( "?q=" + this.domain )
                    .then( response => response.json() )
                    .then( data => this.response = data )
            }
        }
    })
  </script>
</body>
</html>