package sailpoint.services.standard.connector;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;

import sailpoint.connector.ExpiredPasswordException;
import sailpoint.api.IdentityService;
import sailpoint.api.SailPointContext;
import sailpoint.api.SailPointFactory;
import sailpoint.connector.AbstractConnector;
import sailpoint.connector.AuthenticationFailedException;
import sailpoint.connector.Connector;
import sailpoint.connector.ConnectorException;
import sailpoint.connector.ConnectorFactory;
import sailpoint.connector.ObjectNotFoundException;
import sailpoint.object.Application;
import sailpoint.object.AttributeDefinition;
import sailpoint.object.Application.Feature;
import sailpoint.object.Attributes;
import sailpoint.object.Filter;
import sailpoint.object.Identity;
import sailpoint.object.Link;
import sailpoint.object.Partition;
import sailpoint.object.ProvisioningPlan;
import sailpoint.object.ProvisioningPlan.AccountRequest;
import sailpoint.object.ProvisioningPlan.AttributeRequest;
import sailpoint.object.ProvisioningPlan.ObjectRequest;
import sailpoint.object.ProvisioningResult;
import sailpoint.object.Resolver;
import sailpoint.object.ResourceObject;
import sailpoint.object.Rule;
import sailpoint.object.Schema;
import sailpoint.tools.CloseableIterator;
import sailpoint.tools.GeneralException;
import sailpoint.tools.Message;

import org.apache.log4j.Logger;

import openconnector.Util;

import org.owasp.esapi.StringUtilities;

/**
 * 
 * @author menno.pieters@sailpoint.com
 *
 */
public class LogiPlexConnector extends AbstractConnector {

	public final static String LOGIPLEX_ATTR_MASTER_APPLICATION = "masterApplication";
	public final static String LOGIPLEX_AGGREGATION_RULE = "logiPlexAggregationRule";
	public final static String LOGIPLEX_PROVISIONING_RULE = "logiPlexProvisioningRule";
	public final static String LOGIPLEX_PREFIX = "logiPlexPrefix";

	public final static String CONNECTOR_TYPE = "LogiPlex Connector";

	public final static String ARG_ORIGINAL_TARGET_APP = "logiPlexOrginalApplication";

	private final Logger log = Logger.getLogger(LogiPlexConnector.class);

	private Application masterApplication = null;
	private Connector masterConnector = null;
	private SailPointContext context;
	private LogiPlexUtil util = null;

	/**
	 * 
	 * @param application
	 * @throws GeneralException
	 */
	public LogiPlexConnector(final Application application) throws GeneralException {
		super(application);
		if (log.isDebugEnabled()) {
			log.debug(StringUtilities.stripControls(String.format("Constructor: LogiPlexConnector(%s)", application)));
		}
		init(application);
	}

	/**
	 * 
	 * @param application
	 * @param instance
	 * @throws GeneralException
	 */
	public LogiPlexConnector(final Application application, final String instance) throws GeneralException {
		super(application, instance);
		if (log.isDebugEnabled()) {
			log.debug(StringUtilities
					.stripControls(String.format("Constructor: LogiPlexConnector(%s, %s)", application, instance)));
		}
		init(application);
	}

	/**
	 * Called from the constructor to initialize the connector.
	 * 
	 * @param application
	 * @throws GeneralException
	 */
	private void init(Application application) throws GeneralException {
		if (log.isDebugEnabled()) {
			log.debug(StringUtilities.stripControls(String.format("Enter: init(%s)", application)));
		}
		context = SailPointFactory.getCurrentContext();
		String masterApplicationId = application.getStringAttributeValue(LOGIPLEX_ATTR_MASTER_APPLICATION);
		if (application.getId() != null || masterApplicationId != null) {
			if (Util.isNullOrEmpty(masterApplicationId)) {
				Application proxyApplication = application.getProxy();
				if (proxyApplication != null) {
					log.debug("No master application found. Found proxy: checking proxy for master application.");
					masterApplicationId = proxyApplication.getStringAttributeValue(LOGIPLEX_ATTR_MASTER_APPLICATION);
				}
			}
			if (Util.isNullOrEmpty(masterApplicationId)) {
				log.warn("No master application defined");
			} else {
				masterApplication = context.getObject(Application.class, masterApplicationId);
				if (masterApplication == null) {
					throw new GeneralException("Cannot resolve master application " + masterApplicationId);
				}
				masterConnector = ConnectorFactory.getConnector(masterApplication, null);
				if (masterConnector == null) {
					throw new GeneralException("Cannot instantiate master connector");
				}
			}
		} else {
			// Dummy instance
			log.info("Dummy instance, no id - ignoring");
		}
		this.util = new LogiPlexUtil(context, application.getName(), application.getAttributes());
	}

	@Override
	public String getConnectorType() {
		if (log.isDebugEnabled()) {
			log.debug("Enter: getConnectorType()");
		}
		return CONNECTOR_TYPE;
	}

	@SuppressWarnings("deprecation")
	@Override
	public List<Feature> getSupportedFeatures() {
		if (log.isDebugEnabled()) {
			log.debug("Enter: getSupportedFeatures()");
		}
		return this.masterConnector.getSupportedFeatures();
	}

	@Override
	public ResourceObject getObject(final String objectType, final String identityName,
			final Map<String, Object> options) throws ConnectorException {
		if (masterConnector == null) {
			throw new ConnectorException("No master connector set");
		}
		ResourceObject object = this.masterConnector.getObject(objectType, identityName, options);
		Map<String, ResourceObject> objects;
		try {
			objects = util.splitResourceObject(object);
			return objects.get(this.getApplication().getName());
		} catch (GeneralException e) {
			log.error(e);
			throw new ConnectorException(e);
		}
	}

	@Override
	public CloseableIterator<ResourceObject> iterateObjects(final String objectType, final Filter filter,
			final Map<String, Object> options) throws ConnectorException {
		if (masterConnector == null) {
			throw new ConnectorException("No master connector set");
		}
		if (log.isDebugEnabled()) {
			log.debug(StringUtilities
					.stripControls(String.format("Enter: iterateObjects(%s, %s, %s)", objectType, filter, options)));
			Application masterApp = this.masterConnector.getApplication();
			log.debug(StringUtilities.stripControls(String.format("Application for master connector: %s", masterApp)));
			if (masterApp != null) {
				List<Schema> schemas = masterApp.getSchemas();
				if (schemas == null) {
					log.warn("No schemas");
				} else {
					for (Schema schema : schemas) {
						log.debug(StringUtilities
								.stripControls(String.format("Schema defined for %s", schema.getObjectType())));
					}
				}
			}
		}
		CloseableIterator<ResourceObject> masterIterator = this.masterConnector.iterateObjects(objectType, filter,
				options);
		if (log.isDebugEnabled()) {
			log.debug(StringUtilities.stripControls(String.format("Got master iterator: %s)", masterIterator)));
		}
		CloseableIterator<ResourceObject> iterator = null;
		try {
			if (log.isDebugEnabled()) {
				log.debug("Getting LogiPlexIterator using master iterator");
			}
			iterator = new LogiPlexIterator<ResourceObject>(masterIterator, this.util);
		} catch (GeneralException e) {
			log.error(e);
			throw new ConnectorException(e);
		}
		if (log.isTraceEnabled()) {
			log.trace(StringUtilities.stripControls(String.format("Return iterator: %s", iterator)));
		}

		return iterator;
	}

	@Override
	public CloseableIterator<ResourceObject> iterateObjects(Partition partition) throws ConnectorException {
		if (masterConnector == null) {
			throw new ConnectorException("No master connector set");
		}
		if (log.isDebugEnabled()) {
			log.debug(StringUtilities.stripControls(String.format("Enter: iterateObjects(%s)", partition)));
			Application masterApp = this.masterConnector.getApplication();
			log.debug(StringUtilities.stripControls(String.format("Application for master connector: %s", masterApp)));
			if (masterApp != null) {
				List<Schema> schemas = masterApp.getSchemas();
				if (schemas == null) {
					log.warn("No schemas");
				} else {
					for (Schema schema : schemas) {
						log.debug(StringUtilities
								.stripControls(String.format("Schema defined for %s", schema.getObjectType())));
					}
				}
			}
		}
		CloseableIterator<ResourceObject> masterIterator = this.masterConnector.iterateObjects(partition);
		if (log.isDebugEnabled()) {
			log.debug(StringUtilities
					.stripControls(String.format("Got master iterator for partition: %s)", masterIterator)));
		}
		CloseableIterator<ResourceObject> iterator = null;
		try {
			if (log.isDebugEnabled()) {
				log.debug("Getting LogiPlexIterator for partition using master iterator");
			}
			iterator = new LogiPlexIterator<ResourceObject>(masterIterator, this.util);
		} catch (GeneralException e) {
			log.error(e);
			throw new ConnectorException(e);
		}
		if (log.isTraceEnabled()) {
			log.trace(StringUtilities.stripControls(String.format("Return partition iterator: %s", iterator)));
		}

		return iterator;
	}

	@Override
	public List<Partition> getIteratorPartitions(String objectType, int suggestedPartitionCount, Filter filter,
			Map<String, Object> ops) throws ConnectorException {
		if (log.isDebugEnabled()) {
			log.debug(StringUtilities.stripControls(String.format("Enter: getIteratorPartitions(%s, %d, %s, %s)",
					objectType, suggestedPartitionCount, filter, ops)));
		}
		if (masterConnector == null) {
			throw new ConnectorException("No master connector set");
		}
		return masterConnector.getIteratorPartitions(objectType, suggestedPartitionCount, filter, ops);
	}

	/**
	 * Apply default logic to transform the plans for sub-applications into
	 * information for the main application. The default logic will ignore
	 * attribute changes, other than entitlements for sub-application.
	 * 
	 * @param plan
	 * @param identity
	 * @return
	 * @throws GeneralException
	 */
	public ProvisioningPlan runDefaultProvisioningMergeLogic(ProvisioningPlan plan, Identity identity)
			throws GeneralException {
		if (log.isDebugEnabled()) {
			log.debug(StringUtilities
					.stripControls(String.format("Enter: runDefaultProvisioningMergeLogic(%s, %s)", plan, identity)));
		}
		if (plan != null && identity != null) {
			ProvisioningPlan newPlan = new ProvisioningPlan();
			newPlan.setNativeIdentity(plan.getNativeIdentity());
			newPlan.setArguments(plan.getArguments());

			List<AccountRequest> accountRequests = plan.getAccountRequests();
			if (accountRequests != null && !accountRequests.isEmpty()) {
				for (AccountRequest accountRequest : accountRequests) {
					if (log.isTraceEnabled())
						log.trace(accountRequest.toXml());
					switch (accountRequest.getOperation()) {
					case Create:
						Link mainLink = LogiPlexTools.getMainLink(context, identity, this.getApplication(),
								accountRequest);
						if (LogiPlexTools.isMainApplicationRequest(this.getApplication(), accountRequest)
								|| mainLink == null) {
							newPlan.add(accountRequest);
						} else {
							// Just add the entitlements
							List<AttributeRequest> atrqs = new ArrayList<AttributeRequest>();
							List<String> entitlementAttributes = LogiPlexTools
									.getAccountEntitlementAttributes(this.getApplication());
							for (String entitlementAttribute : entitlementAttributes) {
								List<AttributeRequest> eatrqs = accountRequest
										.getAttributeRequests(entitlementAttribute);
								if (eatrqs != null && !eatrqs.isEmpty()) {
									atrqs.addAll(eatrqs);
								}
							}

							// Create a new list and copy modified versions of
							// each attribute request into the list.
							List<AttributeRequest> newAtrqs = new ArrayList<AttributeRequest>();
							if (atrqs != null && !atrqs.isEmpty()) {
								for (AttributeRequest atrq : atrqs) {
									if (ProvisioningPlan.Operation.Set.equals(atrq.getOperation())
											|| ProvisioningPlan.Operation.Add.equals(atrq.getOperation())) {
										atrq.setOperation(ProvisioningPlan.Operation.Add);
										newAtrqs.add(atrq);
									}
								}
							}
							if (!newAtrqs.isEmpty()) {
								AccountRequest nar = new AccountRequest();
								nar.setNativeIdentity(mainLink.getNativeIdentity());
								nar.setInstance(accountRequest.getInstance());
								nar.setOperation(AccountRequest.Operation.Modify);
								nar.setApplication(this.getApplication().getName());
								nar.setArguments(accountRequest.getArguments());
								nar.setAttributeRequests(newAtrqs);
								newPlan.add(nar);
							}
						}
						break;
					case Enable:
					case Disable:
					case Lock:
					case Unlock:
						// Only handle Enable/Disable/Lock/Unlock for the main
						// application,
						// not for any sub-application.
						if (LogiPlexTools.isMainApplicationRequest(this.getApplication(), accountRequest)) {
							newPlan.add(accountRequest);
						}
						break;
					case Modify:
						if (LogiPlexTools.isMainApplicationRequest(this.getApplication(), accountRequest)) {
							newPlan.add(accountRequest);
						} else {
							// For modification of a sub-application, we have to
							// carefully figure out what to do.
							// We need to compare the requested change to the
							// current state.
							Link link = LogiPlexTools.getLink(context, identity, accountRequest);
							if (link != null) {
								List<AttributeRequest> atrqs = new ArrayList<AttributeRequest>();
								List<String> entitlementAttributes = LogiPlexTools
										.getAccountEntitlementAttributes(this.getApplication());
								for (String entitlementAttribute : entitlementAttributes) {
									List<AttributeRequest> eatrqs = accountRequest
											.getAttributeRequests(entitlementAttribute);
									if (eatrqs != null && !eatrqs.isEmpty()) {
										atrqs.addAll(eatrqs);
									}
								}
								List<AttributeRequest> newAtrqs = new ArrayList<AttributeRequest>();
								if (atrqs != null && !atrqs.isEmpty()) {
									for (AttributeRequest atrq : atrqs) {
										// Only handle entitlement attributes.
										String attributeName = atrq.getName();
										if (LogiPlexTools.isAccountEntitlementAttribute(this.getApplication(),
												attributeName)) {
											if (ProvisioningPlan.Operation.Set.equals(atrq.getOperation())) {
												if (LogiPlexTools.isMultiValuedAccountAttribute(this.getApplication(),
														attributeName)) {
													Attributes<String, Object> attributes = link.getAttributes();
													if (attributes != null && !attributes.isEmpty()) {
														List<String> oldValues = (List<String>) attributes
																.getList(attributeName);
														List<String> newValues = new ArrayList<String>();
														Object value = atrq.getValue();
														if (value instanceof List) {
															newValues.addAll((List) value);
														} else if (value != null) {
															newValues.add(value.toString());
														}

														List<String> toAdd = (List<String>) LogiPlexTools
																.getItemsToAdd(oldValues, newValues);
														List<String> toRemove = (List<String>) LogiPlexTools
																.getItemsToRemove(oldValues, newValues);
														for (String val : toRemove) {
															newAtrqs.add(new AttributeRequest(attributeName,
																	ProvisioningPlan.Operation.Remove, val));
														}
														for (String val : toAdd) {
															newAtrqs.add(new AttributeRequest(attributeName,
																	ProvisioningPlan.Operation.Add, val));
														}
													}
												} else {
													newAtrqs.add(atrq);
												}
											} else {
												newAtrqs.add(atrq);
											}
										}
									}
									if (!newAtrqs.isEmpty()) {
										AccountRequest nar = new AccountRequest();
										nar.setNativeIdentity(accountRequest.getNativeIdentity());
										nar.setInstance(accountRequest.getInstance());
										nar.setOperation(AccountRequest.Operation.Modify);
										nar.setApplication(this.getApplication().getName());
										nar.setArguments(accountRequest.getArguments());
										nar.setAttributeRequests(newAtrqs);
										newPlan.add(nar);
									}
								}
							}
						}
						break;
					case Delete:
						if (LogiPlexTools.isMainApplicationRequest(this.getApplication(), accountRequest)) {
							newPlan.add(accountRequest);
						} else {
							// For deletion of a sub-application, we remove all
							// values for entitlements.
							Link link = LogiPlexTools.getLink(context, identity, accountRequest);
							if (link != null) {
								Attributes<String, Object> attributes = link.getAttributes();
								if (attributes != null) {
									List<String> entitlementAttributes = LogiPlexTools
											.getAccountEntitlementAttributes(this.getApplication());
									Map<String, Object> entitlementValues = new HashMap<String, Object>();
									if (!entitlementAttributes.isEmpty()) {
										for (String entitlementAttribute : entitlementAttributes) {
											Object values = (List<String>) attributes.get(entitlementAttribute);
											if (values != null) {
												entitlementValues.put(entitlementAttribute, values);
											}
										}
									}
									if (entitlementValues != null && !entitlementValues.isEmpty()) {
										AccountRequest nar = new AccountRequest();
										nar.setNativeIdentity(accountRequest.getNativeIdentity());
										nar.setInstance(accountRequest.getInstance());
										nar.setOperation(AccountRequest.Operation.Modify);
										nar.setApplication(this.getApplication().getName());
										nar.setArguments(accountRequest.getArguments());
										for (String name : entitlementValues.keySet()) {
											Object values = entitlementValues.get(name);
											if (values instanceof List) {
												for (String value : (List<String>) values) {
													nar.add(new AttributeRequest(name,
															ProvisioningPlan.Operation.Remove, value));
												}
											} else {
												nar.add(new AttributeRequest(name, ProvisioningPlan.Operation.Remove,
														values));
											}
										}
										newPlan.add(nar);
									}
								}
							}
						}
						break;
					default:
						break;
					}
				}
			}

			if (log.isTraceEnabled()) {
				log.trace(newPlan.toXml());
			}
			return newPlan;
		}
		return plan;

	}

	/**
	 * Find and run the LogiPlex Provisioning Rule, if set. Otherwise, use the
	 * default logic.
	 * 
	 * @param plan
	 * @return
	 * @throws ConnectorException
	 * @throws GeneralException
	 */
	private ProvisioningPlan runProvisioningMergeRule(ProvisioningPlan plan)
			throws ConnectorException, GeneralException {
		if (log.isDebugEnabled()) {
			log.debug(StringUtilities.stripControls(String.format("Enter: runProvisioningMergeRule(%s)", plan)));
		}
		String ruleName = this.getApplication().getStringAttributeValue(LOGIPLEX_PROVISIONING_RULE);
		Rule rule = null;

		// If configured, try to retrieve the rule.
		if (Util.isNotNullOrEmpty(ruleName)) {
			log.debug("Looking up provisioning rule: " + ruleName);
			rule = context.getObjectByName(Rule.class, ruleName);
			if (rule == null) {
				throw new ConnectorException(
						StringUtilities.stripControls(String.format("Rule %s not found", ruleName)));
			}
		} else {
			if (log.isInfoEnabled()) {
				log.info("No rule configured, use default logic");
			}
		}

		// Determine identity from plan
		Identity identity = plan.getIdentity();
		if (identity == null) {
			log.debug("Could not get identity directly from the plan, try native identity name from the plan");
			identity = context.getObjectByName(Identity.class, plan.getNativeIdentity());
			if (identity == null) {
				log.warn("Could not get identity from the plan. Identity will be set to null in rule arguments");
			}
		}

		if (rule != null) {
			Map<String, Object> args = new HashMap<String, Object>();
			args.put("context", context);
			args.put("log", log);
			args.put("plan", plan);
			args.put("identity", identity);
			args.put("application", this.getApplication());
			args.put("masterApplication", this.masterApplication);
			args.put("connector", this);
			args.put("masterConnector", this.masterConnector);
			log.debug(StringUtilities.stripControls(
					String.format("Running provisioning rule %s with arguments %s", ruleName, args.toString())));
			Object result = context.runRule(rule, args);
			if (result instanceof ProvisioningPlan) {
				if (log.isTraceEnabled()) {
					log.trace(StringUtilities
							.stripControls(String.format("Modified plan: %s", ((ProvisioningPlan) result).toXml())));
				}
				plan = (ProvisioningPlan) result;
			} else if (result != null) {
				throw new GeneralException(StringUtilities.stripControls(
						String.format("Incorrect result type %s from provisioning rule", result.getClass().getName())));
			}
		} else {
			plan = runDefaultProvisioningMergeLogic(plan, identity);
		}
		return plan;
	}

	@Override
	public ProvisioningResult provision(ProvisioningPlan originalPlan) throws ConnectorException {
		if (log.isDebugEnabled()) {
			log.debug(StringUtilities.stripControls(String.format("Enter: provision(%s)", originalPlan)));
		}
		if (log.isTraceEnabled() && originalPlan != null) {
			try {
				log.trace(StringUtilities.stripControls(String.format("Provisioning plan: %s", originalPlan.toXml())));
			} catch (GeneralException e) {
				log.error(e);
			}
		}
		if (masterApplication == null) {
			throw new ConnectorException("No master application set");
		}
		if (masterConnector == null) {
			throw new ConnectorException("No master connector set");
		}
		try {
			// Clone original plan
			ProvisioningPlan plan = (ProvisioningPlan) originalPlan.deepCopy(context);
			List<AccountRequest> accountRequests = plan.getAccountRequests();
			List<ObjectRequest> objectRequests = plan.getObjectRequests();

			// Store the original target application for later use
			if (accountRequests != null && !accountRequests.isEmpty()) {
				for (AccountRequest accountRequest : accountRequests) {
					accountRequest.put(ARG_ORIGINAL_TARGET_APP, accountRequest.getApplication());
				}
			}
			if (objectRequests != null && !objectRequests.isEmpty()) {
				for (ObjectRequest objectRequest : objectRequests) {
					objectRequest.put(ARG_ORIGINAL_TARGET_APP, objectRequest.getApplication());
				}
			}

			// Process Plan
			plan = runProvisioningMergeRule(plan);

			// Provision through master connector.
			if (plan != null && plan.getAccountRequests() != null
					&& (!plan.getAccountRequests().isEmpty() || !plan.getObjectRequests().isEmpty())) {
				ProvisioningResult masterResult = masterConnector.provision(plan);
				if (masterResult == null) {
					masterResult = new ProvisioningResult();
				}

				// Re-get
				accountRequests = plan.getAccountRequests();
				objectRequests = plan.getObjectRequests();
				if (masterResult.isCommitted()) {
					if (!(masterApplication.supportsFeature(Feature.NO_AGGREGATION)
							|| masterApplication.supportsFeature(Feature.NO_AGGREGATION))) {
						// We should be able to read back the account
						// information
						if (accountRequests != null && !accountRequests.isEmpty()) {
							// Accounts
							for (AccountRequest accountRequest : plan.getAccountRequests()) {
								String nativeIdentity = accountRequest.getNativeIdentity();
								ProvisioningResult subResult = accountRequest.getResult();
								if (subResult == null) {
									subResult = new ProvisioningResult();
									if (masterResult.isCommitted()) {
										subResult.setStatus(ProvisioningResult.STATUS_COMMITTED);
									}
								}
								try {
									ResourceObject object = masterConnector.getObject("account", nativeIdentity,
											new HashMap<String, Object>());
									Map<String, ResourceObject> splitObjects = util.splitResourceObject(object);
									String orginalTarget = (String) accountRequest.getArgument(ARG_ORIGINAL_TARGET_APP);
									ResourceObject resultObject = null;
									if (orginalTarget != null) {
										log.debug(StringUtilities.stripControls(
												String.format("Original target application: %s", orginalTarget)));
										resultObject = splitObjects.get(orginalTarget);
										accountRequest.setApplication(orginalTarget);
									}
									if (resultObject != null) {
										if (log.isTraceEnabled()) {
											log.trace(StringUtilities.stripControls(String.format(
													"Retrieved ResourceObject for account %s on %s: %s", nativeIdentity,
													accountRequest.getApplication(), resultObject.toXml())));
										}
										subResult.setObject(resultObject);
										if (masterResult.getObject() == null) {
											masterResult.setObject(resultObject);
										}
									}
								} catch (Exception e) {
									e.printStackTrace();
									log.error(StringUtilities
											.stripControls(String.format("Error while reading back account: %s", e)));
									subResult.addError(e);
								}
							}
						} else if (objectRequests != null && !objectRequests.isEmpty()) {
							// Groups
							ObjectRequest objectRequest = plan.getObjectRequests().get(0);
							String nativeIdentity = objectRequest.getNativeIdentity();
							objectRequest.getType();
							// TODO: Aggregate back
						}
					}
				}

				// Gather errors and warnings from account and object requests
				// and add these to the original plan and provisioning result
				// returned from the method.
				if (accountRequests != null && !accountRequests.isEmpty()) {
					for (AccountRequest accountRequest : plan.getAccountRequests()) {
						ProvisioningResult subResult = accountRequest.getResult();
						if (subResult != null) {
							List<Message> errors = subResult.getErrors();
							List<Message> warnings = subResult.getWarnings();
							if (errors != null) {
								for (Message message : errors) {
									masterResult.addError(message);
								}
							}
							if (warnings != null) {
								for (Message message : warnings) {
									masterResult.addWarning(message);
								}
							}
						}
					}
				}
				if (objectRequests != null && !objectRequests.isEmpty()) {
					for (ObjectRequest objectRequest : plan.getObjectRequests()) {
						ProvisioningResult subResult = objectRequest.getResult();
						if (subResult != null) {
							List<Message> errors = subResult.getErrors();
							List<Message> warnings = subResult.getWarnings();
							if (errors != null) {
								for (Message message : errors) {
									masterResult.addError(message);
								}
							}
							if (warnings != null) {
								for (Message message : warnings) {
									masterResult.addWarning(message);
								}
							}
						}
					}
				}

				// Add the generated account requests to the original plan
				if (accountRequests != null && !accountRequests.isEmpty()) {
					for (AccountRequest accountRequest : accountRequests) {
						originalPlan.add(accountRequest);
					}
				}
				// Add the generated object requests to the original plan
				if (objectRequests != null && !objectRequests.isEmpty()) {
					for (ObjectRequest objectRequest : objectRequests) {
						originalPlan.add(objectRequest);
					}
				}
				// Set the result(s) on the original plan and return the
				// composed result.
				originalPlan.setResult(masterResult);
				return masterResult;
			} else {
				log.warn("No plan or empty plan - ignoring.");
				return new ProvisioningResult();
			}
		} catch (GeneralException e) {
			log.error(e);
			throw new ConnectorException(e);
		}
	}

	@Override
	public ResourceObject authenticate(String accountId, Map<String, Object> options) throws ConnectorException,
			ObjectNotFoundException, AuthenticationFailedException, ExpiredPasswordException {
		if (log.isDebugEnabled()) {
			log.debug(StringUtilities.stripControls(String.format("Enter: authenticate(%s, %s)", accountId, options)));
		}
		return this.masterConnector.authenticate(accountId, options);
	}

	@Override
	public ResourceObject authenticate(String username, String password) throws ConnectorException,
			ObjectNotFoundException, AuthenticationFailedException, ExpiredPasswordException {
		if (log.isDebugEnabled()) {
			log.debug(
					StringUtilities.stripControls(String.format("Enter: authenticate(%s, %s)", username, "********")));
		}
		return this.masterConnector.authenticate(username, password);
	}

	@Override
	public ProvisioningResult checkStatus(String id) throws ConnectorException, GeneralException {
		if (log.isDebugEnabled()) {
			log.debug(StringUtilities.stripControls(String.format("Enter: checkStatus(%s)", id)));
		}
		return this.masterConnector.checkStatus(id);
	}

	@Override
	public List<AttributeDefinition> getDefaultAttributes() {
		if (log.isDebugEnabled()) {
			log.debug("Enter: getDefaultAttributes()");
		}
		List<AttributeDefinition> defaultAttributes = new ArrayList<AttributeDefinition>();
		defaultAttributes
				.add(new AttributeDefinition("masterApplication", "string", "Master application name or id", true, ""));
		defaultAttributes.add(
				new AttributeDefinition("logiPlexPrefix", "string", "Prefix for generated applications", false, ""));
		return defaultAttributes;
	}

	@Override
	public void testConfiguration() throws ConnectorException {
		if (log.isDebugEnabled()) {
			log.debug("Enter: testConfiguration()");
		}
		if (masterConnector == null) {
			throw new ConnectorException("No master connector set");
		}
		this.masterConnector.testConfiguration();
	}

	@SuppressWarnings("deprecation")
	@Override
	public List<Schema> getDefaultSchemas() {
		if (log.isDebugEnabled()) {
			log.debug("Enter: getDefaultSchemas()");
		}
		return this.masterConnector.getDefaultSchemas();
	}

	@Override
	public Schema discoverSchema(final String objectType, final Map<String, Object> options) throws ConnectorException {
		if (log.isDebugEnabled()) {
			log.debug(
					StringUtilities.stripControls(String.format("Enter: discoverSchema(%s, %s)", objectType, options)));
		}
		if (masterApplication == null) {
			throw new ConnectorException("No master application set");
		}
		if (masterConnector == null) {
			throw new ConnectorException("No master connector set");
		}
		try {
			Schema schema = this.masterConnector.discoverSchema(objectType, options);
			schema = (Schema) schema.deepCopy((Resolver) context);
			schema.setId(null);
			return schema;
		} catch (java.lang.UnsupportedOperationException e) {
			log.warn(StringUtilities.stripControls(
					String.format("Master Connector threw exception while trying to discover schema: %s", e)));
			if (log.isDebugEnabled()) {
				log.debug(StringUtilities.stripControls(
						String.format("Getting Schema for object type %s from master application", objectType)));
			}
			Schema schema = masterApplication.getSchema(objectType);
			if (schema != null) {
				try {
					schema = (Schema) schema.deepCopy((Resolver) context);
					schema.setId(null);
					return schema;
				} catch (GeneralException e1) {
					log.error(e);
					throw new ConnectorException(e);
				}
			}
			throw new ConnectorException(StringUtilities.stripControls(
					String.format("Master application does not have a schema for object type %s", objectType)));
		} catch (GeneralException e) {
			log.error(e);
			throw new ConnectorException(e);
		}
	}

	@Override
	public Map<String, Object> discoverApplicationAttributes(Map<String, Object> options) throws ConnectorException {
		if (log.isDebugEnabled()) {
			log.debug(StringUtilities.stripControls(String.format("Enter: discoverApplicationAttributes(%)", options)));
		}
		return this.masterConnector.discoverApplicationAttributes(options);
	}

	/**
	 * Runtime exception to be thrown in case of an issue while iterating.
	 * 
	 * @author menno.pieters
	 *
	 */
	public class LogiPlexIteratorException extends RuntimeException {

		public LogiPlexIteratorException(Throwable e) {
			super(e);
		}

		/**
		 * 
		 */
		private static final long serialVersionUID = -5924669785877532031L;
	}

	/**
	 * Special iterator class that allows for copying/splitting the
	 * ResourceObjects before returning them.
	 * 
	 * @author menno.pieters@sailpoint.com
	 *
	 * @param <E>
	 */
	public class LogiPlexIterator<E> implements Iterator<ResourceObject>, CloseableIterator<ResourceObject> {

		private final Logger log = Logger.getLogger(LogiPlexIterator.class);
		private CloseableIterator<ResourceObject> masterIterator = null;
		private Queue<ResourceObject> queue = new ConcurrentLinkedQueue<ResourceObject>();
		private LogiPlexUtil util;

		public LogiPlexIterator(CloseableIterator<ResourceObject> masterIterator, LogiPlexUtil util)
				throws GeneralException {
			super();
			if (log.isDebugEnabled()) {
				log.debug(StringUtilities
						.stripControls(String.format("Constructor: LogiPlexIterator(%, %s)", masterIterator, util)));
			}
			if (masterIterator == null) {
				throw new GeneralException("Master iterator must not be null");
			}
			this.masterIterator = masterIterator;
			this.util = util;
		}

		@Override
		public void close() {
			if (log.isDebugEnabled()) {
				log.debug("Enter: close()");
			}
			masterIterator.close();
		}

		/**
		 * Read the next item from the master iterator and run the split rule,
		 * if available. Add the results to the internal queue.
		 * 
		 * @throws GeneralException
		 */
		private void fillQueue() throws GeneralException {
			if (log.isDebugEnabled()) {
				log.debug("Enter: fillQueue()");
			}
			if (masterIterator.hasNext()) {
				ResourceObject object = masterIterator.next();
				Map<String, ResourceObject> map = util.splitResourceObject(object);
				List<ResourceObject> list = util.mapToList(map);
				queue.addAll(list);
			}
		}

		@Override
		public boolean hasNext() {
			if (log.isDebugEnabled()) {
				log.debug("Enter: hasNext()");
			}
			if (!queue.isEmpty()) {
				log.trace("Internal queue still has items");
				return true;
			}
			if (masterIterator.hasNext()) {
				log.trace("Try master iterator");
				try {
					fillQueue();
				} catch (GeneralException e) {
					log.error(e);
					throw new LogiPlexIteratorException(e);
				}
			}
			log.trace(StringUtilities.stripControls(String.format("hasNext(): %b", !queue.isEmpty())));
			return !queue.isEmpty();
		}

		@Override
		public ResourceObject next() {
			if (log.isDebugEnabled()) {
				log.debug("Enter: next()");
			}
			if (queue.isEmpty()) {
				log.debug("Queue is empty. Try to refill queue");
				try {
					fillQueue();
				} catch (GeneralException e) {
					log.error(e);
					throw new LogiPlexIteratorException(e);
				}
			}
			ResourceObject object = queue.poll();
			try {
				log.trace(object.toXml());
			} catch (GeneralException e) {
				log.error(e);
			}
			return object;
		}
	}

	/**
	 * Utility class to support the LogiPlex connector and iterator.
	 * 
	 * @author menno.pieters@sailpoint.com
	 *
	 */
	public class LogiPlexUtil {

		private final Logger log = Logger.getLogger(LogiPlexUtil.class);
		private Attributes<String, Object> settings = null;
		private String applicationName = null;
		private SailPointContext context;
		private Map<String, Object> state = new HashMap<String, Object>();

		/**
		 * Constructor.
		 * 
		 * @param context
		 * @param applicationName
		 * @param settings
		 * @throws GeneralException
		 */
		public LogiPlexUtil(SailPointContext context, String applicationName, Attributes<String, Object> settings)
				throws GeneralException {
			if (log.isTraceEnabled()) {
				log.trace(StringUtilities.stripControls(
						String.format("Constructor: LogiPlexUtil(Context, %s, %s)", applicationName, settings)));
			}
			if (settings == null) {
				throw new GeneralException("No settings supplied");
			}
			if (applicationName == null) {
				throw new GeneralException("No application name supplied");
			}
			this.context = context;
			this.settings = settings;
			this.applicationName = applicationName;
		}

		/**
		 * Get the split rule from the LogiPlex application definition.
		 * 
		 * @return
		 * @throws GeneralException
		 */
		private Rule getSplitRule() throws GeneralException {
			if (log.isTraceEnabled()) {
				log.trace("Enter: getSplitRule");
			}
			String ruleName = settings.getString(LOGIPLEX_AGGREGATION_RULE);
			if (ruleName != null) {
				Rule rule = context.getObjectByName(Rule.class, ruleName);
				if (rule == null) {
					log.error(StringUtilities.stripControls(String.format("Rule %s not found.", ruleName)));
				}
				return rule;
			}
			return null;
		}

		/**
		 * Convert a map of application names and resource objects to a List.
		 * 
		 * @param map
		 * @return
		 */
		public List<ResourceObject> mapToList(Map<String, ResourceObject> map) {
			if (log.isTraceEnabled()) {
				log.trace(StringUtilities.stripControls(String.format("Enter: mapToList(%s)", map)));
			}
			String prefix = settings.getString(LOGIPLEX_PREFIX);
			return mapToList(map, prefix);
		}

		/**
		 * Convert a map of application names and resource objects to a List.
		 * Prefix the application names, if configured to do so and set the
		 * IIQSourceApplication attribute on the ResourceObject, if not yet set.
		 * 
		 * @param map
		 * @param prefix
		 * @return
		 */
		public List<ResourceObject> mapToList(Map<String, ResourceObject> map, String prefix) {
			if (log.isTraceEnabled()) {
				log.trace(StringUtilities.stripControls(String.format("Enter: mapToList(%s, %s)", map, prefix)));
			}
			List<ResourceObject> results = new ArrayList<ResourceObject>();
			if (map != null) {
				for (String key : map.keySet()) {
					ResourceObject object = map.get(key);
					if (!key.equals(applicationName)) {
						String resourceName = object.getString("IIQSourceApplication");
						if (Util.isNullOrEmpty(resourceName)) {
							log.info("Split rule has not set IIQSourceApplication - using key and prefix to generate");
							resourceName = "";
							if (Util.isNotNullOrEmpty(prefix)) {
								resourceName += prefix;
								if (!prefix.endsWith("-")) {
									resourceName += "-";
								}
							}
							resourceName += key;
							log.info(StringUtilities
									.stripControls(String.format("Setting IIQSourceApplication: %s", resourceName)));
							object.put("IIQSourceApplication", resourceName);
						}
					} else {
						// Skip if application equals main application.
					}
					results.add(object);
				}
			}
			return results;
		}

		/**
		 * Split the ResourceObject into separate items per application.
		 * 
		 * @param object
		 * @return
		 * @throws GeneralException
		 */
		@SuppressWarnings("unchecked")
		public Map<String, ResourceObject> splitResourceObject(ResourceObject object) throws GeneralException {
			if (log.isTraceEnabled()) {
				log.trace(StringUtilities.stripControls(String.format("Enter: splitResourceObject(%s)", object)));
			}
			Map<String, ResourceObject> results = new HashMap<String, ResourceObject>();
			Rule rule = getSplitRule();
			if (rule != null) {
				Map<String, Object> args = new HashMap<String, Object>();
				args.put("context", context);
				args.put("log", log);
				args.put("object", object);
				args.put("state", state);
				args.put("applicationName", applicationName);
				args.put("application", context.getObjectByName(Application.class, applicationName));
				Object result = context.runRule(getSplitRule(), args);
				if (result instanceof Map) {
					results.putAll((Map<String, ResourceObject>) result);
				} else if (result != null) {
					throw new GeneralException("Unsupported return type: expected a Map<String, ResourceObject>.");
				}
			} else {
				log.warn("No split rule defined, adding object to default application name.");
				results.put(this.applicationName, object);
			}
			return results;
		}

	}

	/**
	 * Static class with additional helper methods.
	 * 
	 * @author menno.pieters
	 *
	 */
	public static class LogiPlexTools {

		/**
		 * Check whether the account request application is the main
		 * application.
		 * 
		 * @param application
		 * @param req
		 * @return
		 */
		public static boolean isMainApplicationRequest(Application application, AccountRequest req) {
			if (req != null && application != null) {
				return req.getApplication().equals(application.getName());
			}
			return false;
		}

		/**
		 * Get the Link object corresponding to the account request.
		 * 
		 * @param context
		 * @param identity
		 * @param req
		 * @return
		 * @throws GeneralException
		 */
		public static Link getLink(SailPointContext context, Identity identity, AccountRequest req)
				throws GeneralException {
			if (req != null) {
				String nativeIdentity = req.getNativeIdentity();
				if (nativeIdentity != null) {
					IdentityService service = new IdentityService(context);
					return service.getLink(identity, req.getApplication(context), req.getInstance(), nativeIdentity);
				}
			}
			return null;
		}

		/**
		 * Get the Link object for the main application, corresponding to the
		 * account request.
		 * 
		 * @param context
		 * @param identity
		 * @param application
		 * @param req
		 * @return
		 * @throws GeneralException
		 */
		public static Link getMainLink(SailPointContext context, Identity identity, Application application,
				AccountRequest req) throws GeneralException {
			if (req != null) {
				IdentityService service = new IdentityService(context);
				String nativeIdentity = req.getNativeIdentity();
				Link link = null;
				if (nativeIdentity != null) {
					link = service.getLink(identity, application, req.getInstance(), nativeIdentity);
				}
				if (link != null) {
					return link;
				}
				List<Link> links = service.getLinks(identity, application, req.getInstance());
				if (links != null && !links.isEmpty()) {
					return (Link) links.get(0);
				}
			}
			return null;
		}

		/**
		 * Given an application definition, get all the names of attributes that
		 * are marked as entitlements.
		 * 
		 * @param application
		 * @return
		 */
		public static List<String> getAccountEntitlementAttributes(Application application) {
			List<String> attrs = new ArrayList<String>();
			if (application != null) {
				Schema schema = application.getAccountSchema();
				List<String> names = schema.getEntitlementAttributeNames();
				if (names != null && !names.isEmpty()) {
					attrs.addAll(names);
				}
			}
			return attrs;
		}

		/**
		 * Check whether the attribute is listed as an entitlement for the given
		 * application.
		 * 
		 * @param application
		 * @param attributeName
		 * @return
		 */
		public static boolean isAccountEntitlementAttribute(Application application, String attributeName) {
			List<String> entitlementNames = getAccountEntitlementAttributes(application);
			return entitlementNames.contains(attributeName);
		}

		/**
		 * Check whether an application attribute is multi-valued.
		 * 
		 * @param application
		 * @param attributeName
		 * @return
		 * @throws GeneralException
		 */
		public static boolean isMultiValuedAccountAttribute(Application application, String attributeName)
				throws GeneralException {
			if (application != null) {
				Schema schema = application.getAccountSchema();
				AttributeDefinition attributeDefinition = schema.getAttributeDefinition(attributeName);
				if (attributeDefinition != null) {
					return attributeDefinition.isMultiValued();
				}
				throw new GeneralException("Attribute not found");
			}
			throw new GeneralException("Application is not set");
		}

		/**
		 * Compare an old and new list of objects and return those that are in
		 * the old list, but not in the new list.
		 * 
		 * @param oldList
		 * @param newList
		 * @return
		 */
		public static List<?> getItemsToRemove(List<?> oldList, List<?> newList) {
			if (oldList == null || oldList.isEmpty()) {
				// Empty List.
				return new ArrayList<Object>();
			}
			List<Object> toRemove = new ArrayList<Object>();
			if (newList == null || newList.isEmpty()) {
				// New list is empty, remove all old items
				toRemove.addAll(oldList);
			} else {
				// Add items that are not in the new list to the list of items
				// to be removed.
				for (Object o : oldList) {
					if (!newList.contains(o)) {
						toRemove.add(o);
					}
				}
			}
			return toRemove;
		}

		/**
		 * Compare and old and new list of objects and return those that are in
		 * the new list, but not in the old list.
		 * 
		 * @param oldList
		 * @param newList
		 * @return
		 */
		public static List<?> getItemsToAdd(List<?> oldList, List<?> newList) {
			if (newList == null || newList.isEmpty()) {
				// Empty List. Nothing to add/
				return new ArrayList<Object>();
			}
			List<Object> toAdd = new ArrayList<Object>();
			if (oldList == null || oldList.isEmpty()) {
				// New list is empty, remove all old items
				toAdd.addAll(newList);
			} else {
				// Add items that are not in the old list to the list of items
				// to be added.
				for (Object o : newList) {
					if (!oldList.contains(o)) {
						toAdd.add(o);
					}
				}
			}
			return toAdd;
		}
	}

}
