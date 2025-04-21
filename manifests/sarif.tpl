{
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
  "version": "2.1.0",
  "runs": [
    {{- $run_first := true }}
    {{- range $report_index, $report := . }}
    {{- if and $report.Valid (not (eq $report.Message "This resource kind is not supported by kubesec")) -}}
      {{- if $run_first -}}
        {{- $run_first = false -}}
      {{ else -}}
        ,
      {{- end }}
    {
      "tool": {
        "driver": {
          "name": "Kubesec",
          "fullName": "Kubesec Kubernetes Resource Security Policy Validator",
          "rules": [
        {{- $rule_first := true }}
          {{- range .Rules }}
            {{- if $rule_first -}}
              {{- $rule_first = false -}}
            {{ else -}}
              ,
            {{- end }}
            {
              "id": "{{ .ID }}",
              "shortDescription": {
                "text": "{{ .Reason }}"
              },
              "helpUri": "https://github.com/controlplaneio/kubesec",
              "help": {
                "text": "- Reason: {{ .Reason  }}\n- Selector: {{ escapeString .Selector }}\n- Score: {{ .Points }}"
              },
              "messageStrings": {
                "selector": {
                  "text": {{ escapeString .Selector | printf "%q" }}
                }
              },
              "properties": {
                "points": "{{ .Points }}",
                 {{- if lt .Points 0 -}}
                  "security-severity": "9.0"
                {{ else -}}
                  "security-severity": "5.0"
                {{- end }} 
              }
            }
          {{- end -}}
          ]
        }
      },
      "results": [
      {{- $result_first := true }}
      {{- range $result_index, $res := joinSlices .Scoring.Advise .Scoring.Critical -}}
        {{- if $result_first -}}
          {{- $result_first = false -}}
        {{ else -}}
          ,
        {{- end }}
        {
          "ruleId": "{{ $res.ID }}",
          {{- if lt $res.Points 0 -}}
            "level": "error",
          {{ else -}}
            "level": "warning",
          {{- end }}
          "message": {
            "text": {{ endWithPeriod $res.Reason | printf "%q" }},
            "properties": {
              "score": "{{ $res.Points }}",
              "selector": {{ escapeString $res.Selector | printf "%q" }}
            }
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "{{ $report.FileName }}"
                },
                "region": {
                  "startLine": 1,
                  "endLine": 1
                }
              }
            }
          ],
          "partialFingerprints": {
            "primaryLocationLineHash": "hash-{{ $report.FileName }}"
          }
        }
      {{- end -}}
      ],
      "columnKind": "utf16CodeUnits"
    }
  {{- end -}}
  {{- end }}
  ]
}
