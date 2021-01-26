<?php


function run() {

    if ( ! isset( $_REQUEST['domain'] ) ) {
        return;
    }

    $domain = $_REQUEST['domain'];
    $errors = [];

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

    $bash_ip_lookup = <<<EOT
for ip in $( dig $domain +short ); do
    echo "Details on \$ip"
    whois \$ip | grep -E 'NetName:|Organization:|OrgName:'
done
EOT;

  $whois     = shell_exec( "whois $domain | grep -E 'Name Server|Registrar:|Domain Name:|Updated Date:|Creation Date:|Registrar IANA ID:Domain Status:'" );
  $ip_lookup = shell_exec( $bash_ip_lookup );

  if ( empty( $whois ) ) {
    $errors[] = "Domain not found.";
    echo json_encode([
        "errors" => $errors,
      ]);
    die();
  }

  echo json_encode( [
    "whois"       => $whois,
    "dns_records" => [
        "a_empty"                  => shell_exec( "dig $domain +short | sort -n" ),
        "a_www"                    => shell_exec( "dig $domain +short | sort -n" ),
        "cname_autodiscover"       => shell_exec( "dig autodiscover.$domain cname +short | sort -n" ),
        "cname_sip"                => shell_exec( "dig sip.$domain cname +short | sort -n" ),
        "cname_lyncdiscover"       => shell_exec( "dig lyncdiscover.$domain cname +short | sort -n" ),
        "cname_enterpriseregistration" => shell_exec( "dig enterpriseregistration.$domain cname +short | sort -n" ),
        "cname_enterpriseenrollment" => shell_exec( "dig enterpriseenrollment.$domain cname +short | sort -n" ),
        "cname_msoid"              => shell_exec( "dig msoid.$domain cname +short | sort -n" ),
        "mail"                     => shell_exec( "dig $domain MX +short | sort -n" ),
        "txt"                      => shell_exec( "dig $domain TXT +short | sort -n" ),
        "srv_sip_tls"              => shell_exec( "dig _sip._tls.$domain srv +short" ),
        "srv_sipfederationtls_tcp" => shell_exec( "dig _sipfederationtls._tcp.$domain srv +short" ),
        "ns"                       => shell_exec( "dig $domain ns +short | sort -n" ),
    ],
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
            <v-text-field label="Domain" v-model="domain" spellcheck="false" @keydown.enter="lookupDomain()"></v-text-field>
            <v-btn @click="lookupDomain()" class="mb-7">Lookup</v-btn>
            <v-alert type="warning" v-for="error in response.errors">{{ error }}</v-alert>
            <v-row v-if="response.whois && response.whois != ''">
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
                <v-simple-table dense>
                <template v-slot:default>
                <thead>
                    <tr>
                    <th class="text-left">
                        Type
                    </th>
                    <th class="text-left">
                        Name
                    </th>
                    <th class="text-left">
                        Value
                    </th>
                    </tr>
                </thead>
                <tbody>
                    <tr v-show="response.dns_records.a_empty">
                        <td>A</td>
                        <td></td>
                        <td><pre>{{ response.dns_records.a_empty }}</pre></td>
                    </tr>
                    <tr v-show="response.dns_records.a_www">
                        <td>A</td>
                        <td>www</td>
                        <td><pre>{{ response.dns_records.a_www }}</pre></td>
                    </tr>
                    <tr v-show="response.dns_records.mail">
                        <td>MX</td>
                        <td></td>
                        <td><pre>{{ response.dns_records.mail }}</pre></td>
                    </tr>
                    <tr v-show="response.dns_records.cname_autodiscover">
                        <td>CNAME</td>
                        <td>autodiscover</td>
                        <td><pre>{{ response.dns_records.cname_autodiscover }}</pre></td>
                    </tr>
                    <tr v-show="response.dns_records.cname_sip">
                        <td>CNAME</td>
                        <td>sip</td>
                        <td><pre>{{ response.dns_records.cname_sip }}</pre></td>
                    </tr>
                    <tr v-show="response.dns_records.cname_lyncdiscover">
                        <td>CNAME</td>
                        <td>lyncdiscover</td>
                        <td><pre>{{ response.dns_records.cname_lyncdiscover }}</pre></td>
                    </tr>
                    <tr v-show="response.dns_records.cname_enterpriseregistration">
                        <td>CNAME</td>
                        <td>enterpriseregistration</td>
                        <td><pre>{{ response.dns_records.cname_enterpriseregistration }}</pre></td>
                    </tr>
                    <tr v-show="response.dns_records.cname_enterpriseenrollment">
                        <td>CNAME</td>
                        <td>enterpriseenrollment</td>
                        <td><pre>{{ response.dns_records.cname_enterpriseenrollment }}</pre></td>
                    </tr>
                    <tr v-show="response.dns_records.cname_msoid">
                        <td>CNAME</td>
                        <td>msoid</td>
                        <td><pre>{{ response.dns_records.cname_msoid }}</pre></td>
                    </tr>
                    <tr v-show="response.dns_records.txt">
                        <td>TXT</td>
                        <td></td>
                        <td><pre>{{ response.dns_records.txt }}</pre></td>
                    </tr>
                    <tr v-show="response.dns_records.srv_sip_tls">
                        <td>SRV</td>
                        <td>_sip._tls</td>
                        <td><pre>{{ response.dns_records.srv_sip_tls }}</pre></td>
                    </tr>
                    <tr v-show="response.dns_records.srv_sipfederationtls_tcp">
                        <td>SRV</td>
                        <td>_sipfederationtls._tcp</td>
                        <td><pre>{{ response.dns_records.srv_sipfederationtls_tcp }}</pre></td>
                    </tr>
                    <tr v-show="response.dns_records.ns">
                        <td>NS</td>
                        <td></td>
                        <td><pre>{{ response.dns_records.ns }}</pre></td>
                    </tr>
                </tbody>
                </template>
            </v-simple-table>
                   
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
                fetch( "?domain=" + this.domain )
                    .then( response => response.json() )
                    .then( data => {
                            if( data.whois ) { data.whois = data.whois.replace(/^[^\S\r\n]+|[^\S\r\n]+$/gm, "") }
                            this.response = data
                        })
            }
        }
    })
  </script>
</body>
</html>