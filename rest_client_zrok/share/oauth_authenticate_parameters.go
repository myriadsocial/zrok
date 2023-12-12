// Code generated by go-swagger; DO NOT EDIT.

package share

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewOauthAuthenticateParams creates a new OauthAuthenticateParams object,
// with the default timeout for this client.
//
// Default values are not hydrated, since defaults are normally applied by the API server side.
//
// To enforce default values in parameter, use SetDefaults or WithDefaults.
func NewOauthAuthenticateParams() *OauthAuthenticateParams {
	return &OauthAuthenticateParams{
		timeout: cr.DefaultTimeout,
	}
}

// NewOauthAuthenticateParamsWithTimeout creates a new OauthAuthenticateParams object
// with the ability to set a timeout on a request.
func NewOauthAuthenticateParamsWithTimeout(timeout time.Duration) *OauthAuthenticateParams {
	return &OauthAuthenticateParams{
		timeout: timeout,
	}
}

// NewOauthAuthenticateParamsWithContext creates a new OauthAuthenticateParams object
// with the ability to set a context for a request.
func NewOauthAuthenticateParamsWithContext(ctx context.Context) *OauthAuthenticateParams {
	return &OauthAuthenticateParams{
		Context: ctx,
	}
}

// NewOauthAuthenticateParamsWithHTTPClient creates a new OauthAuthenticateParams object
// with the ability to set a custom HTTPClient for a request.
func NewOauthAuthenticateParamsWithHTTPClient(client *http.Client) *OauthAuthenticateParams {
	return &OauthAuthenticateParams{
		HTTPClient: client,
	}
}

/*
OauthAuthenticateParams contains all the parameters to send to the API endpoint

	for the oauth authenticate operation.

	Typically these are written to a http.Request.
*/
type OauthAuthenticateParams struct {

	// Code.
	Code string

	// State.
	State *string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithDefaults hydrates default values in the oauth authenticate params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *OauthAuthenticateParams) WithDefaults() *OauthAuthenticateParams {
	o.SetDefaults()
	return o
}

// SetDefaults hydrates default values in the oauth authenticate params (not the query body).
//
// All values with no default are reset to their zero value.
func (o *OauthAuthenticateParams) SetDefaults() {
	// no default values defined for this parameter
}

// WithTimeout adds the timeout to the oauth authenticate params
func (o *OauthAuthenticateParams) WithTimeout(timeout time.Duration) *OauthAuthenticateParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the oauth authenticate params
func (o *OauthAuthenticateParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the oauth authenticate params
func (o *OauthAuthenticateParams) WithContext(ctx context.Context) *OauthAuthenticateParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the oauth authenticate params
func (o *OauthAuthenticateParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the oauth authenticate params
func (o *OauthAuthenticateParams) WithHTTPClient(client *http.Client) *OauthAuthenticateParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the oauth authenticate params
func (o *OauthAuthenticateParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCode adds the code to the oauth authenticate params
func (o *OauthAuthenticateParams) WithCode(code string) *OauthAuthenticateParams {
	o.SetCode(code)
	return o
}

// SetCode adds the code to the oauth authenticate params
func (o *OauthAuthenticateParams) SetCode(code string) {
	o.Code = code
}

// WithState adds the state to the oauth authenticate params
func (o *OauthAuthenticateParams) WithState(state *string) *OauthAuthenticateParams {
	o.SetState(state)
	return o
}

// SetState adds the state to the oauth authenticate params
func (o *OauthAuthenticateParams) SetState(state *string) {
	o.State = state
}

// WriteToRequest writes these params to a swagger request
func (o *OauthAuthenticateParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param code
	qrCode := o.Code
	qCode := qrCode
	if qCode != "" {

		if err := r.SetQueryParam("code", qCode); err != nil {
			return err
		}
	}

	if o.State != nil {

		// query param state
		var qrState string

		if o.State != nil {
			qrState = *o.State
		}
		qState := qrState
		if qState != "" {

			if err := r.SetQueryParam("state", qState); err != nil {
				return err
			}
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}