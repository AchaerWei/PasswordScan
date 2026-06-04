#!/usr/bin/env groovy
/**
 * Jenkins Init Script — 创建弱口令管理员账户
 * 对应资产表: admin/admin, admin/(空)
 */
import jenkins.model.*
import hudson.security.*

def instance = Jenkins.getInstance()

// 如果尚未配置安全域，创建之
def hudsonRealm = new HudsonPrivateSecurityRealm(false)
hudsonRealm.createAccount("admin", "admin")
instance.setSecurityRealm(hudsonRealm)

// 给 admin 全部权限
def strategy = new FullControlOnceLoggedInAuthorizationStrategy()
strategy.setAllowAnonymousRead(false)
instance.setAuthorizationStrategy(strategy)

instance.save()
println "[weakpass] Jenkins admin user created: admin / admin"
