package controller

import (
	"github.com/go-openapi/runtime/middleware"
	"github.com/openziti-test-kitchen/zrok/rest_model_zrok"
	"github.com/openziti-test-kitchen/zrok/rest_server_zrok/operations/metadata"
	"github.com/sirupsen/logrus"
)

func overviewHandler(_ metadata.OverviewParams, principal *rest_model_zrok.Principal) middleware.Responder {
	tx, err := str.Begin()
	if err != nil {
		logrus.Errorf("error starting transaction: %v", err)
		return metadata.NewOverviewInternalServerError().WithPayload(rest_model_zrok.ErrorMessage(err.Error()))
	}
	defer func() { _ = tx.Rollback() }()
	envs, err := str.FindEnvironmentsForAccount(int(principal.ID), tx)
	if err != nil {
		logrus.Errorf("error finding environments for '%v': %v", principal.Username, err)
		return metadata.NewOverviewInternalServerError().WithPayload(rest_model_zrok.ErrorMessage(err.Error()))
	}
	var out rest_model_zrok.EnvironmentServicesList
	for _, env := range envs {
		svcs, err := str.FindServicesForEnvironment(env.Id, tx)
		if err != nil {
			logrus.Errorf("error finding services for environment '%v': %v", env.ZitiIdentityId, err)
			return metadata.NewOverviewInternalServerError().WithPayload(rest_model_zrok.ErrorMessage(err.Error()))
		}
		es := &rest_model_zrok.EnvironmentServices{
			Environment: &rest_model_zrok.Environment{
				Active:         env.Active,
				Address:        env.Address,
				CreatedAt:      env.CreatedAt.String(),
				Description:    env.Description,
				Host:           env.Host,
				UpdatedAt:      env.UpdatedAt.String(),
				ZitiIdentityID: env.ZitiIdentityId,
			},
		}
		for _, svc := range svcs {
			es.Services = append(es.Services, &rest_model_zrok.Service{
				Active:        svc.Active,
				CreatedAt:     svc.CreatedAt.String(),
				Endpoint:      svc.Endpoint,
				UpdatedAt:     svc.UpdatedAt.String(),
				ZitiServiceID: svc.ZitiServiceId,
			})
		}
		out = append(out, es)
	}
	return metadata.NewOverviewOK().WithPayload(out)
}