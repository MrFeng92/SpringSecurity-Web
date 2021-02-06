package com.feng.securitydemo1.service;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.feng.securitydemo1.entity.Users;
import com.feng.securitydemo1.mapper.UsersMapper;
import com.feng.securitydemo1.mapper.UsersMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * 注入容器，名字必须是和配置类中自动注入的一样，要不然注入不进去
 */
@Service("userDetailsService")
public class MyUserDetailsService implements UserDetailsService
{

    @Autowired
    private UsersMapper usersMapper;

    /**
     * 根据用户输入的用户名从数据库查密码，然后返回用户名和密码
     *
     * @param username 表单中用户输入的用户名
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException
    {
        QueryWrapper queryWrapper = new QueryWrapper();
        //where username=?
        queryWrapper.eq("username", username);

        Users users = usersMapper.selectOne(queryWrapper);
        //判断
        if (users == null)
        {
            //数据库没有用户名，认证失败
            throw new UsernameNotFoundException("用户名不存在！");
        }

        //给数据库角色添加权限或角色，实际中是从数据库查询
        List<GrantedAuthority> authorities = AuthorityUtils.commaSeparatedStringToAuthorityList(
                "admins,ROLE_sale");
        //返回数据库的用户名和密码
        return new User(users.getUsername(), new BCryptPasswordEncoder().encode(users.getPassword()), authorities);
    }
}
