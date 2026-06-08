package com.auth.security.config;

import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.BeanClassLoaderAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.serializer.JacksonJsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.jackson.OAuth2AuthorizationServerJacksonModule;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
import tools.jackson.databind.JacksonModule;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.jsontype.BasicPolymorphicTypeValidator;

import java.util.List;

@Configuration
@EnableRedisHttpSession(redisNamespace = "spring:session:auth", maxInactiveIntervalInSeconds = 3600)
public class SessionConfig implements BeanClassLoaderAware {

    private ClassLoader loader;

    @Bean
    public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
        return new JacksonJsonRedisSerializer<>(createJsonMapper(), Object.class);
    }

    private static JsonMapper createJsonMapper() {
        BasicPolymorphicTypeValidator.Builder builder = BasicPolymorphicTypeValidator.builder()
                .allowIfBaseType(Object.class)
                .allowIfSubType("java.util.concurrent.")
                .allowIfSubType("java.util.")
                .allowIfSubType("org.springframework.security.")
                .allowIfSubType("org.springframework.session.");

        OAuth2AuthorizationServerJacksonModule authorizationServerJacksonModule = new OAuth2AuthorizationServerJacksonModule();
        authorizationServerJacksonModule.configurePolymorphicTypeValidator(builder);
        List<JacksonModule> securityJacksonModules = SecurityJacksonModules.getModules(JdbcOAuth2AuthorizationService.class.getClassLoader(), builder);
        return JsonMapper.builder()
                .addModules(authorizationServerJacksonModule)
                .addModules(securityJacksonModules)
                .build();
    }

    @Override
    public void setBeanClassLoader(@NonNull ClassLoader classLoader) {
        this.loader = classLoader;
    }
}
