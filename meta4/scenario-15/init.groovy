import jenkins.model.*
import hudson.security.*

def inst = Jenkins.getInstance()
def strategy = new GlobalMatrixAuthorizationStrategy()
strategy.add(Jenkins.READ, "anonymous")
strategy.add(hudson.model.Item.READ, "anonymous")
inst.setAuthorizationStrategy(strategy)
inst.setSecurityRealm(new HudsonPrivateSecurityRealm(false))
inst.save()
