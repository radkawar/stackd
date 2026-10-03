package sesv2

import (
	classic "stackd/internal/awsapi/ses"
	api "stackd/internal/awsapi/sesv2"
)

func (c *ClassicService) registerConfigurations() {
	registerClassic(c, "CreateConfigurationSet", c.createConfigurationSet)
	registerClassic(c, "DescribeConfigurationSet", c.describeConfigurationSet)
	registerClassic(c, "DeleteConfigurationSet", c.deleteConfigurationSet)
	registerClassic(c, "ListConfigurationSets", c.listConfigurationSets)
	registerClassic(c, "UpdateConfigurationSetSendingEnabled", c.updateConfigurationSending)
	registerClassic(c, "GetAccountSendingEnabled", c.getAccountSending)
	registerClassic(c, "UpdateAccountSendingEnabled", c.updateAccountSending)
}
func (c *ClassicService) createConfigurationSet(tx Transaction, in *classic.CreateConfigurationSetInput) (*classic.CreateConfigurationSetOutput, error) {
	if in.ConfigurationSet == nil {
		return nil, bad("ConfigurationSet is required.")
	}
	_, e := c.owner.createConfigurationSet(tx, &api.CreateConfigurationSetInput{ConfigurationSetName: (*api.ConfigurationSetName)(in.ConfigurationSet.Name)})
	return &classic.CreateConfigurationSetOutput{}, e
}
func (c *ClassicService) describeConfigurationSet(tx Transaction, in *classic.DescribeConfigurationSetInput) (*classic.DescribeConfigurationSetOutput, error) {
	out, e := c.owner.getConfigurationSet(tx, &api.GetConfigurationSetInput{ConfigurationSetName: (*api.ConfigurationSetName)(in.ConfigurationSetName)})
	if e != nil {
		return nil, e
	}
	if len(in.ConfigurationSetAttributeNames) > 0 {
		return nil, unsupported("Configuration-set event destinations, reputation, tracking and delivery options require their real consumers.")
	}
	return &classic.DescribeConfigurationSetOutput{ConfigurationSet: &classic.ConfigurationSet{Name: (*classic.ConfigurationSetName)(out.ConfigurationSetName)}}, nil
}
func (c *ClassicService) deleteConfigurationSet(tx Transaction, in *classic.DeleteConfigurationSetInput) (*classic.DeleteConfigurationSetOutput, error) {
	_, e := c.owner.deleteConfigurationSet(tx, &api.DeleteConfigurationSetInput{ConfigurationSetName: (*api.ConfigurationSetName)(in.ConfigurationSetName)})
	return &classic.DeleteConfigurationSetOutput{}, e
}
func (c *ClassicService) listConfigurationSets(tx Transaction, in *classic.ListConfigurationSetsInput) (*classic.ListConfigurationSetsOutput, error) {
	out, e := c.owner.listConfigurationSets(tx, &api.ListConfigurationSetsInput{NextToken: (*api.NextToken)(in.NextToken), PageSize: (*api.MaxItems)(in.MaxItems)})
	if e != nil {
		return nil, e
	}
	v := &classic.ListConfigurationSetsOutput{NextToken: (*classic.NextToken)(out.NextToken), ConfigurationSets: make(classic.ConfigurationSets, 0, len(out.ConfigurationSets))}
	for _, name := range out.ConfigurationSets {
		v.ConfigurationSets = append(v.ConfigurationSets, classic.ConfigurationSet{Name: new(classic.ConfigurationSetName(name))})
	}
	return v, nil
}
func (c *ClassicService) updateConfigurationSending(tx Transaction, in *classic.UpdateConfigurationSetSendingEnabledInput) (*classic.UpdateConfigurationSetSendingEnabledOutput, error) {
	_, e := c.owner.putConfigurationSending(tx, &api.PutConfigurationSetSendingOptionsInput{ConfigurationSetName: (*api.ConfigurationSetName)(in.ConfigurationSetName), SendingEnabled: (*api.Enabled)(in.Enabled)})
	return &classic.UpdateConfigurationSetSendingEnabledOutput{}, e
}
func (c *ClassicService) getAccountSending(tx Transaction, in *classic.GetAccountSendingEnabledInput) (*classic.GetAccountSendingEnabledOutput, error) {
	out, e := c.owner.getAccount(tx, &api.GetAccountInput{})
	if e != nil {
		return nil, e
	}
	return &classic.GetAccountSendingEnabledOutput{Enabled: (*classic.Enabled)(out.SendingEnabled)}, nil
}
func (c *ClassicService) updateAccountSending(tx Transaction, in *classic.UpdateAccountSendingEnabledInput) (*classic.UpdateAccountSendingEnabledOutput, error) {
	_, e := c.owner.putAccountSending(tx, &api.PutAccountSendingAttributesInput{SendingEnabled: (*api.Enabled)(in.Enabled)})
	return &classic.UpdateAccountSendingEnabledOutput{}, e
}
