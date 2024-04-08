<?php

require_once 'vendor/autoload.php';
use Badcow\DNS\Classes;
use Badcow\DNS\Zone;
use Badcow\DNS\Rdata\Factory;
use Badcow\DNS\ResourceRecord;
use Badcow\DNS\AlignedBuilder;

function specialTxtFormatter(Badcow\DNS\Rdata\TXT $rdata, int $padding): string {
    //If the text length is less than or equal to 50 characters, just return it unaltered.
    if (strlen($rdata->getText()) <= 500) {
        return sprintf('"%s"', addcslashes($rdata->getText(), '"\\'));
    }

    $returnVal = "(\n";
    $chunks = str_split($rdata->getText(), 500);
    foreach ($chunks as $chunk) {
        $returnVal .= str_repeat(' ', $padding).
            sprintf('"%s"', addcslashes($chunk, '"\\')).
            "\n";
    }
    $returnVal .= str_repeat(' ', $padding) . ")";

    return $returnVal;
}

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

    $zone = new Zone( $domain ."." );
    $zone->setDefaultTtl(3600);

    $bash_ip_lookup = <<<EOT
for ip in $( dig $domain +short ); do
    echo "Details on \$ip"
    whois \$ip | grep -E 'NetName:|Organization:|OrgName:'
done
EOT;

  $whois = shell_exec( "whois $domain | grep -E 'Name Server|Registrar:|Domain Name:|Updated Date:|Creation Date:|Registrar IANA ID:Domain Status:'" );
  $whois = empty( $whois ) ? "" : trim( $whois );

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
    if ( empty( $ip ) ) {
        continue;
    }
    $response           = shell_exec( "whois $ip | grep -E 'NetName:|Organization:|OrgName:'" );
    $response           = empty( $response ) ? "" : trim( $response );
    $ip_lookup[ "$ip" ] = $response;
  }

  $records_to_check = [
    [ "a"     => "" ],
    [ "a"     => "www" ],
    [ "a"     => "*" ],
    [ "cname" => "autodiscover" ],
    [ "cname" => "sip" ],
    [ "cname" => "lyncdiscover" ],
    [ "cname" => "enterpriseregistration" ],
    [ "cname" => "enterpriseenrollment" ],
    [ "cname" => "msoid" ],
    [ "cname" => "_acme-challenge" ],
    [ "cname" => "k2._domainkey" ],
    [ "cname" => "k3._domainkey" ],
    [ "cname" => "ctct1._domainkey" ],
    [ "cname" => "ctct2._domainkey" ],
    [ "cname" => "mail" ],
    [ "cname" => "ftp" ],
    [ "mx"    => "" ],
    [ "mx"    => "mg" ],
    [ "txt"   => "" ],
    [ "txt"   => "_dmarc" ],
    [ "txt"   => "_acme-challenge" ],
    [ "txt"   => "_acme-challenge.www" ],
    [ "txt"   => " _mailchannels" ],
    [ "txt"   => "default._domainkey" ],
    [ "txt"   => "google._domainkey" ],
    [ "txt"   => "mg" ],
    [ "txt"   => "k1._domainkey" ],
    [ "srv"   => "_sip._tls" ],
    [ "srv"   => "_sipfederationtls._tcp" ],
    [ "ns"    => "" ],
    [ "soa"   => "" ],
  ];

  foreach( $records_to_check as $record ) {
    $pre  = "";
    $type = key( $record );
    $name = $record[ $type ];
    if ( ! empty( $name ) ) {
        $pre = "{$name}.";
    }
    $value = shell_exec( "dig $pre$domain $type +short | sort -n" );
    $value = empty( $value ) ? "" : trim( $value );
    if ( empty( $value ) ) {
        continue;
    }
    if ( $type == "soa" ) {
        $record_value = explode( " ", $value );
        $setName = empty( $name ) ? "@" : $name;
        $record  = new ResourceRecord;
        $record->setName( $setName );
        $record->setRdata(Factory::Soa($record_value[0],$record_value[1],$record_value[2],$record_value[3],$record_value[4],$record_value[5],$record_value[6]));
        $zone->addResourceRecord($record);
        continue;
    }
    if ( $type == "ns" ) {
        $record_values = explode( "\n", $value );
        foreach( $record_values as  $record_value ) {
            $setName = empty( $name ) ? "@" : $name;
            $record  = new ResourceRecord;
            $record->setName( $setName );
            $record->setRdata(Factory::Ns($record_value));
            $zone->addResourceRecord($record);
        }
    }
    // Verify A record is not a CNAME record
    if(  $type == "a" && preg_match("/[a-z]/i", $value)){
        $type  = "cname";
        $value = shell_exec( "dig $pre$domain $type +short | sort -n" );
        $value = empty( $value ) ? "" : trim( $value );
        if ( empty( $value ) ) {
            continue;
        }
    }
    if ( $type == "a" ) {
        $record_values = explode( "\n", $value );
        $setName       = empty( $name ) ? "@" : $name;
        foreach( $record_values as $record_value ) {
            $record    = new ResourceRecord;
            $record->setName( $setName );
            $record->setRdata(Factory::A( $record_value ));
            $zone->addResourceRecord($record);
        }
    }
    if ( $type == "cname" ) {
        $setName = empty( $name ) ? $domain : $name;
        $record  = new ResourceRecord;
        $record->setName( $setName );
        $record->setRdata(Factory::Cname($value));
        $zone->addResourceRecord($record);
    }
    if ( $type == "srv" ) {
        $record_values = explode( " ", $value );
        if ( count ( $record_values ) != "4" ) {
            continue;
        }
        $setName = empty( $name ) ? "@" : $name;
        $record  = new ResourceRecord;
        $record->setName( $setName );
        $record->setRdata(Factory::Srv($record_values[0], $record_values[1], $record_values[2], $record_values[3]));
        $zone->addResourceRecord($record);
    }
    if ( $type == "mx" ) {
        $setName       = empty( $name ) ? "@" : $name;
        $record_values = explode( "\n", $value );
        usort($record_values, function ($a, $b) {
            $a_value = explode( " ", $a );
            $b_value = explode( " ", $b );
            return (int) $a_value[0] - (int) $b_value[0];
        });
        foreach( $record_values as $record_value ) {
            $record_value = explode( " ", $record_value );
            if ( count( $record_value ) != "2" ) {
                continue;
            }
            $mx_priority  = $record_value[0];
            $mx_value     = $record_value[1];
            $record       = new ResourceRecord;
            $record->setName( $setName );
            $record->setRdata(Factory::Mx($mx_priority, $mx_value));
            $zone->addResourceRecord($record);
        }
    }
    if ( $type == "txt" ) {
        $record_values = explode( "\n", $value );
        $setName       = empty( $name ) ? "@" : "$name";
        foreach( $record_values as $record_value ) {
            $record = new ResourceRecord;
            $record->setName( $setName );
            $record->setClass('IN');
            $record->setRdata(Factory::Txt(trim($record_value,'"'), 0, 200));
            $zone->addResourceRecord($record);
        }
    }
    $dns_records[] = [ "type" => $type, "name" => $name, "value" => $value ];
  }

  $builder = new AlignedBuilder();
  $builder->addRdataFormatter('TXT', 'specialTxtFormatter');

  echo json_encode( [
    "whois"       => $whois,
    "dns_records" => $dns_records,
    "ip_lookup"   => $ip_lookup,
    "errors"      => [],
    "zone"        => $builder->build($zone)
  ]);
  die();
}

run();

?><!DOCTYPE html>
<html>
<head>
    <title>WHOIS</title>
    <link href="prism.css" rel="stylesheet" />
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
    .theme--light.v-application code {
        padding: 0px;
        background: transparent;
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
            <v-card class="mt-5">
                <v-btn small absolute top right depressed @click="downloadZone()">
                  <v-icon left>mdi-download</v-icon>
                  Download
                </v-btn>
                <pre class="language-dns-zone-file" style="border-radius:4px;border:0px"><code class="language-dns-zone-file">{{ response.zone }}</code></pre>
                <a ref="download_zone" href="#"></a>
            </v-card>
            </v-col>
            </v-row>
        </v-container>
      </v-main>
    </v-app>
  </div>
  <script src="prism.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/vue@2.x/dist/vue.js"></script>
  <script src="https://cdn.jsdelivr.net/npm/vuetify@2.x/dist/vuetify.js"></script>
  <script>
    new Vue({
        el: '#app',
        vuetify: new Vuetify(),
        data: {
            domain: "",
            loading: false,
            response: { whois: "", errors: [], zone: "" }
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
                    .then( done => {
                        Prism.highlightAll()
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
            },
            downloadZone() {
                newBlob = new Blob([this.response.zone], {type: "text/dns"})
                this.$refs.download_zone.download = `${this.domain}.zone`;
                this.$refs.download_zone.href = window.URL.createObjectURL(newBlob);
                this.$refs.download_zone.click();
            }
        }
    })
  </script>
</body>
</html>