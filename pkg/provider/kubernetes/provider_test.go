/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package kubernetes

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	clientgofake "k8s.io/client-go/kubernetes/fake"
	pointer "k8s.io/utils/ptr"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
	fclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	esv1beta1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1beta1"
	v1 "github.com/external-secrets/external-secrets/apis/meta/v1"
)

const (
	testCertificate = `-----BEGIN CERTIFICATE-----
MIIDHTCCAgWgAwIBAgIRAKC4yxy9QGocND+6avTf7BgwDQYJKoZIhvcNAQELBQAw
EjEQMA4GA1UEChMHQWNtZSBDbzAeFw0yMTAzMjAyMDA4MDhaFw0yMTAzMjAyMDM4
MDhaMBIxEDAOBgNVBAoTB0FjbWUgQ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
ggEKAoIBAQC3o6/JdZEqNbqNRkopHhJtJG5c4qS5d0tQ/kZYpfD/v/izAYum4Nzj
aG15owr92/11W0pxPUliRLti3y6iScTs+ofm2D7p4UXj/Fnho/2xoWSOoWAodgvW
Y8jh8A0LQALZiV/9QsrJdXZdS47DYZLsQ3z9yFC/CdXkg1l7AQ3fIVGKdrQBr9kE
1gEDqnKfRxXI8DEQKXr+CKPUwCAytegmy0SHp53zNAvY+kopHytzmJpXLoEhxq4e
ugHe52vXHdh/HJ9VjNp0xOH1waAgAGxHlltCW0PVd5AJ0SXROBS/a3V9sZCbCrJa
YOOonQSEswveSv6PcG9AHvpNPot2Xs6hAgMBAAGjbjBsMA4GA1UdDwEB/wQEAwIC
pDATBgNVHSUEDDAKBggrBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQW
BBR00805mrpoonp95RmC3B6oLl+cGTAVBgNVHREEDjAMggpnb29ibGUuY29tMA0G
CSqGSIb3DQEBCwUAA4IBAQAipc1b6JrEDayPjpz5GM5krcI8dCWVd8re0a9bGjjN
ioWGlu/eTr5El0ffwCNZ2WLmL9rewfHf/bMvYz3ioFZJ2OTxfazqYXNggQz6cMfa
lbedDCdt5XLVX2TyerGvFram+9Uyvk3l0uM7rZnwAmdirG4Tv94QRaD3q4xTj/c0
mv+AggtK0aRFb9o47z/BypLdk5mhbf3Mmr88C8XBzEnfdYyf4JpTlZrYLBmDCu5d
9RLLsjXxhag8xqMtd1uLUM8XOTGzVWacw8iGY+CTtBKqyA+AE6/bDwZvEwVtsKtC
QJ85ioEpy00NioqcF0WyMZH80uMsPycfpnl5uF7RkW8u
-----END CERTIFICATE-----`
)

func TestNewClient(t *testing.T) {
	type fields struct {
		Client       KClient
		ReviewClient RClient
		Namespace    string
	}
	type args struct {
		store     esv1beta1.GenericStore
		kube      kclient.Client
		clientset kubernetes.Interface
		namespace string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    bool
		wantErr bool
	}{
		{
			name:   "invalid store",
			fields: fields{},
			args: args{
				store: &esv1beta1.ClusterSecretStore{
					TypeMeta: metav1.TypeMeta{
						Kind: esv1beta1.ClusterSecretStoreKind,
					},
					Spec: esv1beta1.SecretStoreSpec{
						Provider: &esv1beta1.SecretStoreProvider{},
					},
				},
				kube: fclient.NewClientBuilder().Build(),
			},
			wantErr: true,
		},
		{
			name:   "test referent auth return",
			fields: fields{},
			args: args{
				store: &esv1beta1.ClusterSecretStore{
					TypeMeta: metav1.TypeMeta{
						Kind: esv1beta1.ClusterSecretStoreKind,
					},
					Spec: esv1beta1.SecretStoreSpec{
						Provider: &esv1beta1.SecretStoreProvider{
							Kubernetes: &esv1beta1.KubernetesProvider{
								Server: esv1beta1.KubernetesServer{
									CABundle: []byte(testCertificate),
								},
								Auth: esv1beta1.KubernetesAuth{
									Token: &esv1beta1.TokenAuth{
										BearerToken: v1.SecretKeySelector{
											Name: "foo",
											Key:  "token",
										},
									},
								},
							},
						},
					},
				},
				namespace: "",
				kube:      fclient.NewClientBuilder().Build(),
				clientset: clientgofake.NewSimpleClientset(),
			},
			want: true,
		},
		{
			name:   "auth fail results in error",
			fields: fields{},
			args: args{
				store: &esv1beta1.ClusterSecretStore{
					TypeMeta: metav1.TypeMeta{
						Kind: esv1beta1.ClusterSecretStoreKind,
					},
					Spec: esv1beta1.SecretStoreSpec{
						Provider: &esv1beta1.SecretStoreProvider{
							Kubernetes: &esv1beta1.KubernetesProvider{
								Server: esv1beta1.KubernetesServer{
									CABundle: []byte(testCertificate),
								},
								RemoteNamespace: "remote",
								Auth: esv1beta1.KubernetesAuth{
									Token: &esv1beta1.TokenAuth{
										BearerToken: v1.SecretKeySelector{
											Name:      "foo",
											Namespace: pointer.To("default"),
											Key:       "token",
										},
									},
								},
							},
						},
					},
				},
				namespace: "foobarothernamespace",
				clientset: clientgofake.NewSimpleClientset(),
				kube:      fclient.NewClientBuilder().Build(),
			},
			wantErr: true,
		},
		{
			name:   "test auth",
			fields: fields{},
			args: args{
				store: &esv1beta1.ClusterSecretStore{
					TypeMeta: metav1.TypeMeta{
						Kind: esv1beta1.ClusterSecretStoreKind,
					},
					Spec: esv1beta1.SecretStoreSpec{
						Provider: &esv1beta1.SecretStoreProvider{
							Kubernetes: &esv1beta1.KubernetesProvider{
								Server: esv1beta1.KubernetesServer{
									CABundle: []byte(testCertificate),
								},
								RemoteNamespace: "remote",
								Auth: esv1beta1.KubernetesAuth{
									Token: &esv1beta1.TokenAuth{
										BearerToken: v1.SecretKeySelector{
											Name:      "foo",
											Namespace: pointer.To("default"),
											Key:       "token",
										},
									},
								},
							},
						},
					},
				},
				namespace: "foobarothernamespace",
				clientset: clientgofake.NewSimpleClientset(),
				kube: fclient.NewClientBuilder().WithObjects(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "foo",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"token": []byte("1234"),
					},
				}).Build(),
			},
			want: true,
		},
		{
			name:   "test kubeconfig",
			fields: fields{},
			args: args{
				store: &esv1beta1.ClusterSecretStore{
					TypeMeta: metav1.TypeMeta{
						Kind: esv1beta1.ClusterSecretStoreKind,
					},
					Spec: esv1beta1.SecretStoreSpec{
						Provider: &esv1beta1.SecretStoreProvider{
							Kubernetes: &esv1beta1.KubernetesProvider{
								Server: esv1beta1.KubernetesServer{
									CABundle: []byte(testCertificate),
								},
								RemoteNamespace: "remote",
								Auth: esv1beta1.KubernetesAuth{
									KubeConfig: &v1.SecretKeySelector{
										Name:      "kubeconfig-secret",
										Namespace: pointer.To("default"),
										Key:       "config",
									},
								},
							},
						},
					},
				},
				namespace: "default",
				clientset: clientgofake.NewSimpleClientset(),
				kube: fclient.NewClientBuilder().WithObjects(&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "kubeconfig-secret",
						Namespace: "default",
					},
					Data: map[string][]byte{
						"config": []byte(`apiVersion: v1
clusters:
- cluster:
    certificate-authority-data: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlDcnpDQ0FaY0NGQjIwb1Nud29MRWt3WTRNSWJkNmhNMmltOVBvTUEwR0NTcUdTSWIzRFFFQkN3VUFNQlF4DQpFakFRQmdOVkJBTU1DV3h2WTJGc2FHOXpkREFlRncweU16RXhNamd3T1RFNE5UZGFGdzB5TXpFeU1qZ3dPVEU0DQpOVGRhTUJReEVqQVFCZ05WQkFNTUNXeHZZMkZzYUc5emREQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQDQpBRENDQVFvQ2dnRUJBT0dnTzRKQmlscm5zbWNkNXdNakNYMGg5ZGY1dEI3TGh2Z0daT3d2R0w4SWxGK251QlRqDQpYM0ZRdGJJQXhPcGVwaFpTRUxUN0VIa2FMSGFsUWJxNkF1VUUvM1BhRUh4QmNnTUl2TzFIbXRFdzVwWTZCT2NuDQpXL0pjTzdHZFg2b2xtZ1VRakh1RzJiM3dxOFRIRWFVblduODY0NzFXMHhCZDdSZDdEOSswK3BpZUpwcmxnT0MxDQpqdHZsMkh1bTM4bVBneHh1SFhzbWdWVmEvNDhTWGNvT2ZESUpwV01DbFNUcWFFNVhBRGFRRXRxQ0ZiUmIzZ29lDQprbUEvL2l6eHpCRm5lL21mbk5BYlAwd2hUOXc0ejNXSExVMkdTc3o4bXQ4OTlWMGZ3TkRuZzBTM0FQclptSW4wDQpNVkF2bkM1Rm9hb0VQYVl0VkpQYXZJWXFaRXd2eU4zZmg2Y0NBd0VBQVRBTkJna3Foa2lHOXcwQkFRc0ZBQU9DDQpBUUVBVGVwekVhOERqQUl0Z1V0VU54anN5VFY5d0VqMUZTYk1mVjU0L2J4bXJtTkl0ZjFBYzBkTlluZVgzQ3ZoDQpXYU1SaUdCdEJMeW9UMTUvN2MvR0tBRS9DNmlXS1RjMTlpcnpXcm9MZVBZakZtSTRFUlRZWHR0eW9ia0p4OG9IDQpMMWtmTlFTYUpaZ2hNemd5cWFCWVgxRmhVZ0U5eVpsbVJFeUlXOXVEMUZxZWE3Y29MdXJLWkxiWHpWR2dZcmFhDQp3YXZVWHh6TGRoTW5hZGhNa2hKbnVmeFRURkZXaXo5eHovcnFjNERmbU9RSGlSTnI2bnQ1Z2J4dXRwY2srMCtNDQpTZEdFcDNvUmphbVdIdndzNnkyVUVKN1lvV1hmUHJQRmNYeWlERFY2bkhsNUg0elhpRDlBVW0xU3lqeFJjNmFtDQozVFRRR1gzZDlXekJYU2lrVVBhZk5EcjBzdz09DQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0t
    server: https://localhost:8080
  name: dummyName
contexts:
- context:
    cluster: dummyName
    user: dummyUser
  name: dummyContext
current-context: dummyContext
kind: Config
preferences: {}
users:
- name: dummyUser
  user:
    token: dummyToken
`),
					},
				}).Build(),
			},
			want: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (&Provider{}).newClient(context.Background(), tt.args.store, tt.args.kube, tt.args.clientset, tt.args.namespace)
			if (err != nil) != tt.wantErr {
				t.Errorf("ProviderKubernetes.NewClient() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.want {
				assert.NotNil(t, got)
			} else {
				assert.Nil(t, got)
			}
		})
	}
}
