<?php


function run() {

    if ( ! isset( $_REQUEST['domain'] ) ) {
        return;
    }

    $domain      = $_REQUEST['domain'];
    $errors      = [];
    $ip_lookup   = [];
    $dns_records = [];

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

  $whois = trim( shell_exec( "whois $domain | grep -E 'Name Server|Registrar:|Domain Name:|Updated Date:|Creation Date:|Registrar IANA ID:Domain Status:'" ) );

  if ( empty( $whois ) ) {
    $errors[] = "Domain not found.";
    echo json_encode([
        "errors" => $errors,
      ]);
    die();
  }

  $whois = explode( "\n", $whois );
  foreach( $whois as $key => $record ) {
    $split  = explode( ":", trim( $record ) );
    $name   = trim( $split[0] );
    $value  = trim( $split[1] );
    if ( $name == "Name Server" || $name == "Domain Name"  ) {
        $value = strtolower( $value );
    }
    $whois[ $key ] = [ "name" => $name, "value" => $value ];
  }
  $whois     = array_map("unserialize", array_unique(array_map("serialize", $whois)));
  $col_name  = array_column($whois, 'name');
  $col_value = array_column($whois, 'value');
  array_multisort($col_name, SORT_ASC, $col_value, SORT_ASC, $whois);
  $ips      = explode( "\n", trim( shell_exec( "dig $domain +short" ) ) );
  foreach ( $ips as $ip ) {
    $ip_lookup[ "$ip" ] = trim( shell_exec( "whois $ip | grep -E 'NetName:|Organization:|OrgName:'" ) );
  }

  $records_to_check = [
    [ "a"     => "" ],
    [ "a"     => "www" ],
    [ "cname" => "autodiscover" ],
    [ "cname" => "sip" ],
    [ "cname" => "lyncdiscover" ],
    [ "cname" => "enterpriseregistration" ],
    [ "cname" => "enterpriseenrollment" ],
    [ "cname" => "msoid" ],
    [ "mx"    => "" ],
    [ "txt"   => "" ],
    [ "srv"   => "_sip._tls" ],
    [ "srv"   => "_sipfederationtls._tcp" ],
    [ "ns"    => "" ],
  ];

  foreach( $records_to_check as $record ) {
    $pre  = "";
    $type = key( $record );
    $name = $record[ $type ];
    if ( ! empty( $name ) ) {
        $pre = "{$name}.";
    }
    $value = trim( shell_exec( "dig $pre$domain $type +short | sort -n" ) );
    if ( ! empty( $value ) ) {
        $dns_records[] = [ "type" => $type, "name" => $name, "value" => $value ];
    }
  }

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
    .multiline {
        white-space: pre-wrap;
    }
  </style>
</head>
<body>
  <div id="app" v-cloak>
    <v-app>
      <v-main>
        <v-container>
            <v-text-field label="Domain" v-model="domain" spellcheck="false" @keydown.enter="lookupDomain()"></v-text-field>
            <v-btn @click="lookupDomain()" :loading="loading" class="mb-7">
                Lookup
                <template v-slot:loader><v-progress-circular :size="22" :width="1" color="primary" indeterminate></v-progress-circular></template>
            </v-btn>
            <v-alert type="warning" v-for="error in response.errors">{{ error }}</v-alert>
            <v-row v-if="response.whois && response.whois != ''">
            <v-col md="5" cols="12">
            <v-card>
                <v-card-title>Whois</v-card-title>
                <v-card-text>
                <v-simple-table dense>
                <template v-slot:default>
                <thead>
                    <tr>
                    <th class="text-left">
                        Name
                    </th>
                    <th class="text-left">
                        Value
                    </th>
                    </tr>
                </thead>
                <tbody>
                    <tr v-for='record in response.whois'>
                        <td>{{ record.name }}</td>
                        <td>{{ record.value }}</td>
                    </tr>
                </tbody>
                </template>
                </v-simple-table>
                </v-card-text>
                </v-card>
            </v-card>
            <v-card class="mt-5">
                <v-card-title>IP information</v-card-title>
                <v-card-text>
                    <template v-for='(rows, ip) in response.ip_lookup'>
                    <div class="mt-3">Details for {{ ip }}</div>
                    <v-simple-table dense>
                    <template v-slot:default>
                    <thead>
                        <tr>
                        <th class="text-left">
                            Name
                        </th>
                        <th class="text-left">
                            Value
                        </th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr v-for='row in rows.split("\n")'>
                            <td>{{ row.split( ":" )[0] }}</td>
                            <td>{{ row.split( ":" )[1] }}</td>
                        </tr>
                    </tbody>
                    </template>
                    </v-simple-table>
                    </template>
                </v-card-text>
                </v-card>
            </v-card>
            </v-col>
            <v-col md="7" cols="12">
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
                    <tr v-for="record in response.dns_records">
                        <td>{{ record.type }}</td>
                        <td>{{ record.name }}</td>
                        <td class="multiline">{{ record.value }}</td>
                    </tr>
                </tbody>
                </template>
                </v-simple-table>
                </v-card-text>
                </v-card>
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
            loading: false,
            response: { whois: "", errors: [] }
        },
        methods: {
            lookupDomain() {
                this.loading = true
                this.domain = this.extractHostname( this.domain )
                fetch( "?domain=" + this.domain )
                    .then( response => response.json() )
                    .then( data => {
                        this.loading = false
                        this.response = data
                    })
            },
            extractHostname( url ) {
                var hostname;
                //find & remove protocol (http, ftp, etc.) and get hostname

                if (url.indexOf("//") > -1) {
                    hostname = url.split('/')[2];
                } else {
                    hostname = url.split('/')[0];
                }

                //find & remove port number
                hostname = hostname.split(':')[0];
                //find & remove "?"
                hostname = hostname.split('?')[0];

                return hostname;
            }
        }
    })
  </script>
</body>
</html>