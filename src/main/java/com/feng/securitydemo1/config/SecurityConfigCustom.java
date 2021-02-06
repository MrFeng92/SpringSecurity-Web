package com.feng.securitydemo1.config;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.rememberme.JdbcTokenRepositoryImpl;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import javax.sql.DataSource;

/**
 * 自定义用户名密码获取方式
 */
@Configuration
@MapperScan("com.feng.securitydemo1.mapper")
public class SecurityConfigCustom extends WebSecurityConfigurerAdapter
{
    @Autowired
    private UserDetailsService userDetailsService;

    //注入数据源
    @Autowired
    private DataSource dataSource;

    /**
     * 设置用户名和密码获取方式
     *
     * @param auth
     * @throws Exception
     */
    protected void configure(AuthenticationManagerBuilder auth) throws Exception
    {
        auth.userDetailsService(userDetailsService).passwordEncoder(passwordEncoder());
    }

    /**
     * 注入passwordEncoder对象
     *
     * @return
     */
    @Bean
    public PasswordEncoder passwordEncoder()
    {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception
    {
        //退出
        http.logout().logoutUrl("/logout").
                logoutSuccessUrl("/test/hello").permitAll();

        //配置没有权限访问跳转自定义页面
        http.exceptionHandling().accessDeniedPage("/unauth.html");

        http.formLogin()   //自定义自己编写的登录页面
                .loginPage("/login.html")  //登录页面设置
                .loginProcessingUrl("/user/login")   //登录访问路径
                .defaultSuccessUrl("/success.html").permitAll()  //登录成功之后，跳转路径
//                .failureUrl("/unauth.html")
                .and().authorizeRequests().antMatchers("/", "/test/hello", "/user/login").permitAll() //设置哪些路径可以直接访问，不需要认证
                //当前登录用户，只有具有admins权限才可以访问这个路径
                //1 hasAuthority方法
                //.antMatchers("/test/index").hasAuthority("admins")
                //2 hasAnyAuthority方法,设置多个权限，满足其中一个就行
                // .antMatchers("/test/index").hasAnyAuthority("admins,manager")
                //3 hasRole方法 源码会自动拼接  ROLE_  ROLE_sale
                .antMatchers("/test/index").hasRole("sale")

                .anyRequest().authenticated()

                //记住我，自动登录
                .and().rememberMe().tokenRepository(persistentTokenRepository())
                 .tokenValiditySeconds(60)//设置有效时长，单位秒
                .userDetailsService(userDetailsService)
                // .and().csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse());
                .and().csrf().disable();  //关闭csrf防护
//        super.configure(http);
    }

    //配置对象
    @Bean
    public PersistentTokenRepository persistentTokenRepository()
    {
        JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
        jdbcTokenRepository.setDataSource(dataSource);
//        jdbcTokenRepository.setCreateTableOnStartup(true);//第一次登录自动生成表
        return jdbcTokenRepository;
    }
}
